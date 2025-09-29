import os
import asyncio
import json
from pathlib import Path
from aiohttp import web, WSMsgType

# Use mounted data dir when available; default to /data (suitable for container mounts)
BASE_DIR = Path(os.environ.get("LOG_DATA_DIR", "/data")).resolve()

FILES = {
    "commands": BASE_DIR / "commands.log",
    "credentials": BASE_DIR / "credentials.log",
}

# Sets of websocket.WebSocketResponse objects per key
clients = {
    "commands": set(),
    "credentials": set(),
}


async def broadcast(key: str, message: dict):
    payload = json.dumps(message)
    dead = []
    for ws in clients[key]:
        try:
            await ws.send_str(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients[key].discard(ws)


async def send_initial(ws, key: str):
    path = FILES[key]
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")  # create empty file
    # Read whole file and send as lines
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    await ws.send_str(json.dumps({"type": "initial", "lines": lines}))


async def tail_file_and_broadcast(key: str, interval: float = 0.5):
    path = FILES[key]
    # Ensure file exists
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    # Open and seek to end to only send new lines as they arrive
    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                line = line.rstrip("\n")
                await broadcast(key, {"type": "append", "line": line})
                continue
            # If EOF, check if file was truncated (size < current position)
            try:
                current_pos = f.tell()
                size = path.stat().st_size
                if size < current_pos:
                    # file was truncated/rotated: reopen from start
                    f.close()
                    with path.open("r", encoding="utf-8", errors="replace") as f2:
                        f = f2
                        # send remaining lines from start if any
                        for new_line in f:
                            new_line = new_line.rstrip("\n")
                            await broadcast(key, {"type": "append", "line": new_line})
                else:
                    await asyncio.sleep(interval)
            except FileNotFoundError:
                # file removed; recreate and continue
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("")
                await asyncio.sleep(interval)


async def websocket_handler(request):
    key = request.match_info.get("key")
    if key not in FILES:
        return web.Response(status=404, text="Unknown log key")
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    clients[key].add(ws)

    # Send initial file content
    try:
        await send_initial(ws, key)
    except Exception:
        # fail silently for initial send
        pass

    # Keep connection alive; remove when client disconnects
    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            # optional: handle ping/pong or client requests
            if msg.data == "ping":
                await ws.send_str(json.dumps({"type": "pong"}))
        elif msg.type == WSMsgType.ERROR:
            break

    clients[key].discard(ws)
    return ws


async def start_background_tasks(app):
    app["tail_commands"] = asyncio.create_task(tail_file_and_broadcast("commands"))
    app["tail_credentials"] = asyncio.create_task(tail_file_and_broadcast("credentials"))


async def cleanup_background_tasks(app):
    for k in ("tail_commands", "tail_credentials"):
        task = app.get(k)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


def create_app():
    app = web.Application()
    app.router.add_get("/ws/{key}", websocket_handler)  # /ws/commands or /ws/credentials
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    return app


if __name__ == "__main__":
    # show effective config for easier debugging in container environment
    print(f"Starting log-exporter; data dir = {BASE_DIR}, port = 8081}")
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=int("8081"))
