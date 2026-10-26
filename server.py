# Relay-Own server -- plain Python stdlib, no Cloudflare, no Tailscale,
# no KV, no Durable Objects, no first-poll key lock.
#
# Run locally:  RELAY_KEY=<your-key> python3 server.py
# Run on Render: set Environment Variable RELAY_KEY in the dashboard,
# start command: python server.py  (PORT is provided by Render).
#
# Storage: in-memory only. One pending command slot, a results map,
# and lastSeen. A server restart loses pending commands and results;
# that is acceptable: the operator simply re-sends the command.
# No JSON file backup is used, on purpose: a file on a free host is
# not reliably persistent either, and in-memory keeps the code simple.
#
# Auth: fixed secret only. The secret is the RELAY_KEY environment
# variable, set by Kayden in the Render dashboard. It must match
# relay_key.txt on the PC, character for character.
# - If RELAY_KEY is missing on the server, authenticated routes
#   return 503 with the exact body 'RELAY_KEY not set', not 403.
# - If the incoming X-Relay-Key does not match, 403 'wrong key'.
# - No key is ever stored, logged, or returned. Only SHA-256 hashes
#   are compared, in memory, per request.
# - Nothing is set by the first poll. Polling can never lock the
#   mailbox to a wrong key.
#
# Routes:
#   POST /command  operator, X-Relay-Key, {"id","text"}
#                  -> {"queued":true,"id","connected":bool}
#   GET  /pending  PC agent, X-Relay-Key
#                  -> {"command":{"id","text"}} or {"command":null}
#                  Consumes pending (deletes it) before returning it.
#   POST /result   PC agent, X-Relay-Key, {"id",...}
#                  -> {"ok":true}
#   GET  /result?id=<id>  operator, X-Relay-Key
#                  -> {"ready":true,"result":{...}} or {"ready":false}
#                  Deletes the result after it is read once.
#   GET  /status   no key needed
#                  -> {"connected":bool,"pending":0|1,"results":n}
#                  Never returns a key, a command, or a result.
#                  connected = PC polled within the last 30 seconds.

import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOCK = threading.Lock()
PENDING = None  # dict {"id","text"} or None
RESULTS = {}    # id -> result dict
LAST_SEEN = 0.0  # epoch seconds of last successful PC poll


def secret_hash(value):
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def check_key(handler):
    """Return (ok, status, message). Missing secret -> 503, wrong -> 403."""
    secret = os.environ.get("RELAY_KEY", "")
    if not secret:
        return False, 503, "RELAY_KEY not set"
    incoming = handler.headers.get("X-Relay-Key") or ""
    if not incoming:
        return False, 403, "wrong key"
    if hmac.compare_digest(secret_hash(incoming), secret_hash(secret)):
        return True, 200, ""
    return False, 403, "wrong key"


def connected():
    return (time.time() - LAST_SEEN) < 30 if LAST_SEEN else False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        # Never log keys, commands, or results.
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text, status):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > 1_000_000:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return None

    def do_GET(self):
        global LAST_SEEN, PENDING
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/status":
            with LOCK:
                self._json({
                    "connected": connected(),
                    "pending": 1 if PENDING is not None else 0,
                    "results": len(RESULTS),
                })
            return
        if path == "/pending":
            ok, status, msg = check_key(self)
            if not ok:
                self._text(msg, status)
                return
            with LOCK:
                LAST_SEEN = time.time()
                command = PENDING
                PENDING = None
            self._json({"command": command})
            return
        if path == "/result":
            ok, status, msg = check_key(self)
            if not ok:
                self._text(msg, status)
                return
            query = parse_qs(parsed.query)
            rid = (query.get("id") or [""])[0]
            if not rid:
                self._text("id required", 400)
                return
            with LOCK:
                result = RESULTS.pop(rid, None)
            if result is None:
                self._json({"ready": False})
            else:
                self._json({"ready": True, "result": result})
            return
        self._text("not found", 404)

    def do_POST(self):
        global PENDING
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/command":
            ok, status, msg = check_key(self)
            if not ok:
                self._text(msg, status)
                return
            body = self._read_json()
            if not body or not isinstance(body.get("id"), str) or not body["id"] \
                    or not isinstance(body.get("text"), str) or not body["text"]:
                self._text("id and text required", 400)
                return
            with LOCK:
                PENDING = {"id": body["id"], "text": body["text"]}
                is_connected = connected()
            self._json({"queued": True, "id": body["id"], "connected": is_connected})
            return
        if path == "/result":
            ok, status, msg = check_key(self)
            if not ok:
                self._text(msg, status)
                return
            body = self._read_json()
            if not body or not isinstance(body.get("id"), str) or not body["id"]:
                self._text("id required", 400)
                return
            with LOCK:
                RESULTS[body["id"]] = body
            self._json({"ok": True})
            return
        self._text("not found", 404)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"Relay-Own server listening on port {port}", flush=True)
    print("RELAY_KEY set:", bool(os.environ.get("RELAY_KEY")), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
