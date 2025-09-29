#!/usr/bin/env python3
# smtp_honeypot/app.py
# Simple SMTP acceptor: forwards DATA to LLM for an acknowledgement, returns sanitized ack.
# Logs meta + raw into /data.

import os
import json
import time
import hashlib
import tempfile
import re
from pathlib import Path
from datetime import datetime
import socket
import threading
import httpx

# Paths
DATA = Path("/data")
META = DATA / "meta"
RAW = DATA / "raws"
META.mkdir(parents=True, exist_ok=True)
RAW.mkdir(parents=True, exist_ok=True)

# Config
LLM_BACKEND = os.getenv("LLM_BACKEND", "http://100.105.46.22:11434/api/generated")
ALLOWED_MODELS = [m for m in os.getenv("ALLOWED_MODELS", "llama3.1:8b").split(",") if m]
SMTP_PROMPT_TEMPLATE = os.getenv("SMTP_PROMPT_TEMPLATE", "")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8.0"))
REQUEST_PREVIEW_LIMIT = int(os.getenv("REQUEST_PREVIEW_LIMIT", "1024"))
RESPONSE_PREVIEW_LIMIT = int(os.getenv("RESPONSE_PREVIEW_LIMIT", "1000"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "20"))

INTERNAL_PATTERNS = [
    r"\/?api\/generated",
    r"host\.docker\.internal",
    r"100\.105\.46\.22",
    r"host-gateway",
    r"\bhoneypot\b",
    r"\bproxy\b",
    r"\binternal\b"
]
_internal_regex = re.compile("|".join(INTERNAL_PATTERNS), flags=re.IGNORECASE)

_rate_store = {}

def now_iso(): return datetime.utcnow().isoformat() + "Z"

def atomic_write_json(path: Path, obj: dict):
    data = json.dumps(obj, ensure_ascii=False, indent=2)
    fd, tmp = tempfile.mkstemp(prefix="meta-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, str(path))
    except Exception:
        try: os.remove(tmp)
        except: pass

def save_meta(record: dict):
    record["recorded_at"] = now_iso()
    rnd = hashlib.sha256((record.get("client_ip","") + record["recorded_at"] + str(time.time())).encode()).hexdigest()
    atomic_write_json(META / f"{rnd}.json", record)
    return str(META / f"{rnd}.json")

def save_raw(b: bytes):
    ts = now_iso()
    fname = f"smtpraw-{hashlib.sha256((ts+str(time.time())).encode()).hexdigest()[:20]}.bin"
    p = RAW / fname
    try:
        p.write_bytes(b)
        return str(p)
    except Exception:
        return None

def rate_limited(ip: str) -> bool:
    t = time.time()
    arr = [x for x in _rate_store.get(ip, []) if x > t - RATE_LIMIT_WINDOW]
    if len(arr) >= RATE_LIMIT_MAX:
        _rate_store[ip] = arr
        return True
    arr.append(t); _rate_store[ip] = arr
    return False

def sanitize_text(s: str) -> str:
    if s is None: return ""
    s_clean = _internal_regex.sub("[redacted]", s)
    s_clean = re.sub(r"https?://[^\s/]+", "[redacted]", s_clean)
    if len(s_clean) > RESPONSE_PREVIEW_LIMIT * 5:
        s_clean = s_clean[:RESPONSE_PREVIEW_LIMIT * 5] + "...[truncated]"
    return s_clean

def render_template(template: str, mapping: dict) -> str:
    if not template: return ""
    out = template
    for k,v in mapping.items():
        out = out.replace("{" + k + "}", str(v))
    return out

def call_llm(model: str, prompt: str):
    payload = {"model": model, "prompt": prompt}
    headers = {"X-Honeypot-Proxy":"pihoneypot", "Content-Type":"application/json"}
    with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
        r = client.post(LLM_BACKEND, json=payload, headers=headers)
        r.raise_for_status()
        try:
            return r.json(), r.status_code
        except Exception:
            return r.text, r.status_code

def handle_client(conn, addr):
    client_ip = addr[0]
    save_meta({"type":"smtp_connect","client_ip":client_ip,"peer":repr(addr)})
    conn.send(b"220 pihoneypot ESMTP ready\r\n")
    buffer = b""
    data_mode = False
    mail_buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buffer += chunk
            try:
                text = chunk.decode(errors="replace")
            except:
                text = str(chunk)
            if data_mode:
                mail_buf += chunk
                # end of data: line with single dot
                if b"\r\n.\r\n" in mail_buf or b"\n.\n" in mail_buf:
                    data_mode = False
                    # preview
                    preview = mail_buf.decode(errors="replace")[:REQUEST_PREVIEW_LIMIT]
                    save_raw(mail_buf)
                    mapping = {"client_ip": client_ip, "data_preview": preview}
                    prompt = render_template(SMTP_PROMPT_TEMPLATE, mapping) or f"You are an SMTP server. DATA preview:\\n{preview}\\nReturn a single-line SMTP acknowledgement."
                    model = ALLOWED_MODELS[0] if ALLOWED_MODELS else "llama3.1:8b"
                    # rate-limit
                    if rate_limited(client_ip):
                        conn.send(b"250 OK\r\n")
                        save_meta({"type":"smtp_rate_limited","client_ip":client_ip})
                        mail_buf = b""; continue
                    try:
                        backend_resp, status = call_llm(model, prompt)
                    except Exception as e:
                        save_meta({"type":"smtp_llm_error","client_ip":client_ip,"error":str(e)})
                        conn.send(b"250 OK\r\n")
                        mail_buf = b""; continue

                    if isinstance(backend_resp, dict):
                        out = backend_resp.get("body") or backend_resp.get("text") or json.dumps(backend_resp)
                    else:
                        out = str(backend_resp)
                    out = sanitize_text(out).splitlines()[0][:300]
                    save_meta({"type":"smtp_data","client_ip":client_ip,"data_preview":preview[:REQUEST_PREVIEW_LIMIT],"llm_ack":out})
                    conn.send((f"250 {out}\r\n").encode())
                    mail_buf = b""
            else:
                cmd = text.strip()
                save_meta({"type":"smtp_cmd","client_ip":client_ip,"cmd":cmd})
                cmd_u = cmd.upper()
                if cmd_u.startswith("HELO") or cmd_u.startswith("EHLO"):
                    conn.send(b"250 pihoneypot\r\n")
                elif cmd_u.startswith("MAIL FROM"):
                    conn.send(b"250 OK\r\n")
                elif cmd_u.startswith("RCPT TO"):
                    conn.send(b"250 OK\r\n")
                elif cmd_u == "DATA":
                    conn.send(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    data_mode = True
                    mail_buf = b""
                elif cmd_u.startswith("QUIT"):
                    conn.send(b"221 Bye\r\n"); break
                else:
                    conn.send(b"250 OK\r\n")
    except Exception as e:
        save_meta({"type":"smtp_error","client_ip":client_ip,"error":str(e)})
    finally:
        try: conn.close()
        except: pass

def start(bind="0.0.0.0", port=25):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    s.bind((bind, port)); s.listen(50)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start()

