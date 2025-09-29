#!/usr/bin/env python3
# http_honeypot/app.py
# HTTP honeypot: forward requests to LLM backend, return sanitized LLM response to client,
# and persist minimal meta + raw for dashboard.

import os
import re
import json
import time
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime
from flask import Flask, request, Response, jsonify
import httpx

# ---------- CONFIG ----------
DATA = Path("/data")
META = DATA / "meta"
RAW = DATA / "raws"
META.mkdir(parents=True, exist_ok=True)
RAW.mkdir(parents=True, exist_ok=True)

LLM_BACKEND = os.getenv("LLM_BACKEND", "http://100.105.46.22:11434/api/generated")
ALLOWED_MODELS = set([m for m in os.getenv("ALLOWED_MODELS", "llama3.1:8b").split(",") if m])
HTTP_PROMPT_TEMPLATE = os.getenv("HTTP_PROMPT_TEMPLATE", "")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8.0"))
REQUEST_PREVIEW_LIMIT = int(os.getenv("REQUEST_PREVIEW_LIMIT", "1024"))
RESPONSE_PREVIEW_LIMIT = int(os.getenv("RESPONSE_PREVIEW_LIMIT", "2000"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "20"))

# Patterns to redact from any output sent to client
INTERNAL_PATTERNS = [
    r"\/?api\/generated",
    r"host\.docker\.internal",
    r"100\.105\.46\.22",  # your LLM IP — redact occurrences
    r"host-gateway",
    r"\bhoneypot\b",
    r"\bproxy\b",
    r"\binternal\b"
]
_internal_regex = re.compile("|".join(INTERNAL_PATTERNS), flags=re.IGNORECASE)

# hop-by-hop headers not allowed to be forwarded
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "upgrade", "transfer-encoding", "content-length"
}

# ---------- APP ----------
app = Flask(__name__)
_rate_store = {}  # ip -> [timestamps]

# ---------- helpers ----------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def client_ip():
    # if behind a proxy, you may prefer X-Forwarded-For; here simple remote_addr
    return request.remote_addr or "unknown"

def atomic_write_json(path: Path, obj: dict):
    data = json.dumps(obj, ensure_ascii=False, indent=2)
    fd, tmp = tempfile.mkstemp(prefix="meta-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass

def save_meta(record: dict):
    record["recorded_at"] = now_iso()
    rnd = hashlib.sha256((record.get("client_ip","") + record["recorded_at"] + str(time.time())).encode()).hexdigest()
    path = META / f"{rnd}.json"
    atomic_write_json(path, record)
    return str(path)

def save_raw(content: bytes):
    ts = now_iso()
    fname = f"raw-{hashlib.sha256((ts+str(time.time())).encode()).hexdigest()[:20]}.bin"
    p = RAW / fname
    try:
        p.write_bytes(content)
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

def sanitize_text_for_client(s: str) -> str:
    if s is None:
        return ""
    # redact internal patterns
    s_clean = _internal_regex.sub("[redacted]", s)
    # remove explicit http://host mentions (keeps paths)
    s_clean = re.sub(r"https?://[^\s/]+", "[redacted]", s_clean)
    # truncate to avoid huge bodies leaking internals
    if len(s_clean) > RESPONSE_PREVIEW_LIMIT * 5:
        s_clean = s_clean[:RESPONSE_PREVIEW_LIMIT * 5] + "...[truncated]"
    return s_clean

def sanitize_headers_for_client(h: dict) -> dict:
    out = {}
    for k, v in (h or {}).items():
        if not k:
            continue
        lk = k.lower()
        if lk in HOP_BY_HOP:
            continue
        v_str = str(v)
        v_clean = _internal_regex.sub("[redacted]", v_str)
        # normalize Server header to a realistic value if missing or suspicious
        out[k] = v_clean
    if "Server" not in {k for k in out.keys()}:
        out["Server"] = "Apache/2.4.41 (Ubuntu)"
    return out

def render_template(template: str, mapping: dict) -> str:
    if not template:
        return ""
    out = template
    for k, v in mapping.items():
        out = out.replace("{" + k + "}", str(v))
    return out

def call_llm(model: str, prompt: str):
    payload = {"model": model, "prompt": prompt}
    headers = {"X-Honeypot-Proxy": "pihoneypot", "Content-Type": "application/json"}
    with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
        r = client.post(LLM_BACKEND, json=payload, headers=headers)
        r.raise_for_status()
        try:
            return r.json(), r.status_code, r.headers.get("content-type", "application/json")
        except Exception:
            return r.text, r.status_code, r.headers.get("content-type", "text/plain")

# ---------- routes ----------
@app.route("/ping", methods=["GET"])
def ping():
    return "ok", 200

@app.route("/api/generated", methods=["POST"])
def api_generated():
    ip = client_ip()
    if rate_limited(ip):
        return jsonify({"error":"rate_limited"}), 429
    if not request.is_json:
        return jsonify({"error":"expected_json"}), 400
    payload = request.get_json(silent=True) or {}
    model = (payload.get("model") or "").strip()
    if ALLOWED_MODELS and model not in ALLOWED_MODELS:
        return jsonify({"error":"model_not_allowed"}), 400

    # save small preview of the incoming LLM request (not full prompt)
    try:
        preview = json.dumps(payload, ensure_ascii=False)[:REQUEST_PREVIEW_LIMIT]
    except Exception:
        preview = str(payload)[:REQUEST_PREVIEW_LIMIT]
    save_meta({"type":"llm_request","client_ip":ip,"model":model,"request_preview":preview})

    # forward the payload to configured LLM backend
    try:
        backend_resp, status_code, content_type = call_llm(model, payload.get("prompt","") if isinstance(payload, dict) else "")
    except httpx.HTTPStatusError as e:
        save_meta({"type":"llm_forward_error","client_ip":ip,"error":f"status {e.response.status_code}"})
        return jsonify({"error":"backend_error"}), 502
    except Exception as e:
        save_meta({"type":"llm_forward_error","client_ip":ip,"error":str(e)})
        return jsonify({"error":"backend_unavailable"}), 502

    # persist raw + meta
    if isinstance(backend_resp, dict):
        raw_bytes = json.dumps(backend_resp).encode()
        preview_text = json.dumps(backend_resp)[:RESPONSE_PREVIEW_LIMIT]
    else:
        raw_bytes = str(backend_resp).encode()
        preview_text = str(backend_resp)[:RESPONSE_PREVIEW_LIMIT]
    raw_path = save_raw(raw_bytes)
    save_meta({"type":"llm_response","client_ip":ip,"model":model,"backend_status":status_code,"response_preview":preview_text,"raw_path":raw_path})

    # sanitize and return to client
    if isinstance(backend_resp, dict) and "status" in backend_resp and "body" in backend_resp:
        status = int(backend_resp.get("status", 200))
        resp_headers = backend_resp.get("headers", {}) or {}
        resp_body = str(backend_resp.get("body", ""))
        safe_headers = sanitize_headers_for_client(resp_headers)
        safe_body = sanitize_text_for_client(resp_body)
        body_bytes = safe_body.encode()
        return Response(body_bytes, status=status, headers=safe_headers, content_type=safe_headers.get("Content-Type", "text/plain"))
    elif isinstance(backend_resp, dict):
        # return the JSON but sanitized
        safe_json = sanitize_text_for_client(json.dumps(backend_resp))
        return Response(safe_json.encode(), status=status_code, content_type="application/json")
    else:
        safe = sanitize_text_for_client(str(backend_resp))
        return Response(safe.encode(), status=status_code, content_type=content_type or "text/plain")

# catch-all: build prompt (from template or default), forward to LLM, sanitize response
@app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
@app.route("/<path:path>", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
def forward_all(path):
    ip = client_ip()
    if rate_limited(ip):
        return jsonify({"error":"rate_limited"}), 429

    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("authorization","cookie")}
    body_bytes = request.get_data() or b""
    body_preview = body_bytes.decode(errors="replace")[:2000]

    mapping = {
        "client_ip": ip,
        "method": request.method,
        "path": "/" + path,
        "headers": json.dumps(headers, ensure_ascii=False, indent=2),
        "body": body_preview
    }

    prompt = render_template(HTTP_PROMPT_TEMPLATE, mapping) or (
        f"You are an HTTP server emulator. Incoming request:\nMETHOD: {request.method}\nPATH: /{path}\nHEADERS:\n{mapping['headers']}\n\nBODY PREVIEW:\n{body_preview}\n\n"
        "Return either a JSON object {\"status\":.., \"headers\":{...}, \"body\":\"...\"} or a plain text body (honeypot will wrap as 200 text/plain)."
    )

    model_hint = request.headers.get("X-Model") or (list(ALLOWED_MODELS)[0] if ALLOWED_MODELS else "llama3.1:8b")

    # save request meta
    save_meta({"type":"http_request","client_ip":ip,"method":request.method,"path":"/"+path,"headers_preview":json.dumps(headers)[:REQUEST_PREVIEW_LIMIT],"body_preview":body_preview[:REQUEST_PREVIEW_LIMIT]})

    try:
        backend_resp, status_code, content_type = call_llm(model_hint, prompt)
    except httpx.HTTPStatusError as e:
        save_meta({"type":"llm_forward_error","client_ip":ip,"error":f"status {e.response.status_code}"})
        return jsonify({"error":"backend_error"}), 502
    except Exception as e:
        save_meta({"type":"llm_forward_error","client_ip":ip,"error":str(e)})
        return jsonify({"error":"backend_unavailable"}), 502

    # persist backend raw + meta
    if isinstance(backend_resp, dict):
        raw_bytes = json.dumps(backend_resp).encode()
        preview = json.dumps(backend_resp)[:RESPONSE_PREVIEW_LIMIT]
    else:
        raw_bytes = str(backend_resp).encode()
        preview = str(backend_resp)[:RESPONSE_PREVIEW_LIMIT]
    raw_path = save_raw(raw_bytes)
    save_meta({"type":"http_forward_response","client_ip":ip,"path":"/"+path,"response_preview":preview,"raw_path":raw_path})

    # sanitize and return
    if isinstance(backend_resp, dict) and "status" in backend_resp and "body" in backend_resp:
        status = int(backend_resp.get("status", 200))
        resp_headers = backend_resp.get("headers", {}) or {}
        resp_body = str(backend_resp.get("body", ""))
        safe_headers = sanitize_headers_for_client(resp_headers)
        safe_body = sanitize_text_for_client(resp_body)
        return Response(safe_body.encode(), status=status, headers=safe_headers, content_type=safe_headers.get("Content-Type", "text/plain"))
    elif isinstance(backend_resp, dict):
        safe_json = sanitize_text_for_client(json.dumps(backend_resp))
        return Response(safe_json.encode(), status=status_code, content_type="application/json")
    else:
        safe = sanitize_text_for_client(str(backend_resp))
        return Response(safe.encode(), status=status_code, content_type=content_type or "text/plain")

if __name__ == "__main__":
    # run with Flask built-in for local tests; in Docker use CMD ["python","app.py"]
    app.run(host="0.0.0.0", port=80)

