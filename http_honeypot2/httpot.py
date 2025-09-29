#!/usr/bin/env python3
"""
Minimal HTTP honeypot (Python stdlib only).
- Logs requests as JSON lines (one per request) to http-honeypot.log (rotates).
- Fake endpoints: /, /admin (login form), /login (Basic-Auth challenge), /robots.txt,
  /server-status, /wp-login.php (slow), /phpmyadmin (slow), everything else => 404.
- Captures: client IP/port, method, path, query, headers, Basic-Auth creds (if any),
  POST body (truncated), user agent, cookies.
- Optional artificial delay (global) + extra delay on “interesting” paths.
"""
import base64
import json
import logging
import re
import time
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse, parse_qs

# ------------- Config via CLI -------------
parser = argparse.ArgumentParser(description="Simple HTTP honeypot")
parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
parser.add_argument("--log", default="http-honeypot.log", help="Path to log file")
parser.add_argument("--max-log-bytes", type=int, default=10_000_000, help="Rotate size")
parser.add_argument("--backups", type=int, default=5, help="Log rotation backups")
parser.add_argument("--delay", type=float, default=0.0, help="Global per-request delay seconds")
parser.add_argument("--slow-extra", type=float, default=2.5, help="Extra delay for juicy paths")
parser.add_argument("--server-banner", default='Apache/2.4.41 (Ubuntu)', help="Fake Server header")
args, _ = parser.parse_known_args()

# ------------- Logging -------------
logger = logging.getLogger("honeypot")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(args.log, maxBytes=args.max_log_bytes, backupCount=args.backups)
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

JUICY_PATHS = re.compile(r"/(wp-login\.php|xmlrpc\.php|phpmyadmin|server-status|\.git|\.env|admin|login)", re.I)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def decode_basic_auth(auth_header: str):
    """
    Returns (username, password) if Authorization: Basic ... is present and decodes, else (None, None).
    """
    if not auth_header:
        return None, None
    try:
        scheme, payload = auth_header.split(" ", 1)
        if scheme.lower() != "basic":
            return None, None
        raw = base64.b64decode(payload.strip()).decode("utf-8", "replace")
        if ":" in raw:
            user, pwd = raw.split(":", 1)
            return user, pwd
    except Exception:
        pass
    return None, None

def json_safe(o):
    try:
        json.dumps(o)
        return o
    except Exception:
        return str(o)

class HoneyHandler(BaseHTTPRequestHandler):
    server_version = args.server_banner
    sys_version = ""  # suppress Python http.server disclosure

    # Common responder
    def _send(self, code=200, body=b"", content_type="text/html; charset=utf-8", headers=None):
        # Global delay
        if args.delay > 0:
            time.sleep(args.delay)
        # Extra tarpit for juicy paths
        if JUICY_PATHS.search(self.path or "") and args.slow_extra > 0:
            time.sleep(args.slow_extra)

        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", args.server_banner)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Set a tracking cookie if absent
        if "Cookie" not in self.headers:
            self.send_header("Set-Cookie", f"HPSESSID={int(time.time())}; Path=/; HttpOnly; SameSite=Lax")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        self.wfile.write(body)

    # Logging (JSON line per request)
    def _log_request(self, method, status_code, parsed, body_bytes):
        # Truncate large bodies
        max_body = 4096
        body_preview = body_bytes[:max_body] if body_bytes else b""
        auth = self.headers.get("Authorization", "")
        user, pwd = decode_basic_auth(auth)

        entry = {
            "ts": now_iso(),
            "client_ip": self.client_address[0] if self.client_address else None,
            "client_port": self.client_address[1] if self.client_address else None,
            "method": method,
            "path": parsed.path,
            "query": {k: v if len(v) > 1 else v[0] for k, v in parse_qs(parsed.query).items()},
            "status": status_code,
            "headers": {k: self.headers.get(k) for k in self.headers.keys()},
            "user_agent": self.headers.get("User-Agent"),
            "cookies": self.headers.get("Cookie"),
            "auth_scheme": (auth.split(" ", 1)[0] if auth else None),
            "basic_user": user,
            "basic_pass": pwd,
            "body_len": len(body_bytes) if body_bytes else 0,
            "body_sample_b64": base64.b64encode(body_preview).decode("ascii") if body_bytes else None,
            "is_juicy_path": bool(JUICY_PATHS.search(parsed.path or "")),
        }
        logger.info(json.dumps(json_safe(entry), ensure_ascii=False))

    # Utilities to read the request body safely
    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > 0:
            return self.rfile.read(min(length, 10_000_000))  # hard cap 10MB
        return b""

    # --- Handlers ---
    def do_GET(self):
        parsed = urlparse(self.path or "/")
        status = 200

        if parsed.path in ("/", ""):
            body = f"""<html><head><title>Welcome</title></head>
<body>
<h1>Welcome</h1>
<p>This site is under maintenance. Please check back later.</p>
<!-- intentionally boring -->
</body></html>"""
            self._send(200, body)
            status = 200

        elif parsed.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /login\n")
            status = 200

        elif parsed.path == "/server-status":
            fake = f"""<html><head><title>Apache Status</title></head>
<body><h1>Apache Server Status for localhost</h1>
<dl><dt>Server Version:</dt><dd>{args.server_banner}</dd>
<dt>Server MPM:</dt><dd>event</dd>
<dt>Server Uptime:</dt><dd>{int(time.time()) % 100000} seconds</dd></dl>
<table border="0"><tr><th>PID</th><th>SS</th><th>Req</th><th>Client</th><th>VHost</th><th>Request</th></tr>
<tr><td>1234</td><td>10</td><td>1</td><td>{self.client_address[0]}</td><td>example.local</td><td>GET {parsed.path}</td></tr>
</table></body></html>"""
            self._send(200, fake)
            status = 200

        elif parsed.path in ("/admin", "/admin/"):
            form = """<html><head><title>Admin Login</title></head>
<body>
<h2>Admin</h2>
<form method="POST" action="/admin">
  <label>User: <input name="user"></label><br>
  <label>Pass: <input type="password" name="pass"></label><br>
  <button type="submit">Login</button>
</form>
</body></html>"""
            self._send(200, form)
            status = 200

        elif parsed.path in ("/login", "/login/"):
            # Force a Basic-Auth prompt
            self._send(401, "Authentication required.", headers={"WWW-Authenticate": 'Basic realm="Restricted"'})
            status = 401

        elif parsed.path in ("/wp-login.php", "/phpmyadmin"):
            self._send(200, "<html><body><h1>OK</h1></body></html>")
            status = 200

        else:
            body = f"""<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL {parsed.path} was not found on this server.</p></body></html>"""
            self._send(404, body)
            status = 404

        # Log
        self._log_request("GET", status, parsed, b"")

    def do_POST(self):
        parsed = urlparse(self.path or "/")
        body = self._read_body()
        status = 200

        # Fake “processing” for form posts
        if parsed.path in ("/admin", "/admin/", "/wp-login.php", "/login", "/login/"):
            # Pretend auth failed to encourage more attempts
            self._send(401, "<html><body><p>Invalid credentials.</p></body></html>",
                       headers={"WWW-Authenticate": 'Basic realm="Restricted"'})
            status = 401
        else:
            self._send(200, "<html><body><p>OK</p></body></html>")
            status = 200

        # Log after responding
        self._log_request("POST", status, parsed, body)

    # Quiet the default console log
    def log_message(self, fmt, *args):
        return

def main():
    server = ThreadingHTTPServer((args.host, args.port), HoneyHandler)
    print(f"[+] HTTP honeypot listening on {args.host}:{args.port} (banner: {args.server_banner})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
