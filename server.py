"""Relay-Own v2 server.

Plain Python, standard library only. No paid service, no new package.

What changed from v1:
- A real queue. Jobs wait in a list, in order, with an id and a status.
  A new job never overwrites an old job.
- Long poll. The PC holds one request open (up to 25 seconds). The
  second a job is queued, the server answers that open request. The
  PC no longer checks every 1 second and misses nothing in between.
- Job status. queued, running, done, failed, cancelled.
- Progress. A long job can post progress chunks while it runs.
- Job history saved to a file, so a server restart does not erase it.
  Jobs that were running when the server stopped come back as queued.
- Alerts. Every done or failed job is also kept in a short alerts list,
  so the phone can be told when a job finishes or fails.
- Old v1 routes still work: POST /command, GET /pending, POST /result,
  GET /result?id=, GET /status.

Run locally for testing only:
  RELAY_KEY=<a-test-key-you-make-up> python3 server.py
Run on Render:
  Set Environment Variable RELAY_KEY in the dashboard.
  Start command: python server.py  (PORT is provided by Render).

Auth, same as v1:
- The secret is the RELAY_KEY environment variable on the server.
  It must match relay_key.txt on the PC, character for character.
- If RELAY_KEY is missing, authenticated routes return 503 with the
  exact body 'RELAY_KEY not set', not 403.
- If the incoming X-Relay-Key does not match, 403 'wrong key'.
- No key is ever stored, logged, or returned. Only SHA-256 hashes
  are compared, in memory, per request.
- Never put a real key in this file, in chat, or in a log.

Routes (all except /status need X-Relay-Key):
  POST /command    {"id","text"} -> {"queued":true,"id","position","connected"}
  GET  /pending    ?wait=25 (agent) -> {"command":{"id","text"}} or null.
                   The job returned is marked running. Long poll only
                   when wait is given; without wait it answers at once.
  POST /result     {"id","ok","text","photo_b64"} -> {"ok":true}
                   If the job was already cancelled, the status stays
                   cancelled and the result is kept as a note.
  POST /progress   {"id","text","pct"} -> {"ok":true}
  POST /cancel     {"id"} -> cancels one queued or running job.
  POST /cancel_all {} -> cancels every queued and running job.
  GET  /job?id=    -> one full job, or 404.
  GET  /jobs       -> last 50 jobs, newest last.
  GET  /alerts     -> last 20 done/failed alerts.
  GET  /result?id= -> v1 style, one-time read of a job result.
  GET  /status     -> no key needed, no job text, no result text.
"""

import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOCK = threading.Lock()
COND = threading.Condition(LOCK)
JOBS = {}          # id -> job dict
QUEUE = []         # job ids, in order, still queued
RESULTS = {}       # id -> result dict, for v1-style one-time reads
ALERTS = []        # list of {id, ok, text, time}
LAST_SEEN = 0.0
JOBS_FILE = os.environ.get(
    "RELAY_JOBS_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "jobs_history.json"),
)


def secret_hash(value):
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def check_key(handler):
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


def save_jobs():
    try:
        tmp = JOBS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                {"jobs": list(JOBS.values()), "alerts": ALERTS[-20:]},
                f, indent=2,
            )
        os.replace(tmp, JOBS_FILE)
    except Exception:
        pass


def load_jobs():
    global ALERTS
    try:
        if not os.path.exists(JOBS_FILE):
            return
        with open(JOBS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for job in data.get("jobs", []):
            if job.get("status") == "running":
                job["status"] = "queued"
                if job["id"] not in QUEUE:
                    QUEUE.append(job["id"])
            JOBS[job["id"]] = job
            if job.get("status") in ("done", "failed", "cancelled"):
                RESULTS[job["id"]] = {
                    "type": "result", "id": job["id"],
                    "ok": job.get("ok", False), "text": job.get("result", ""),
                    "photo_b64": job.get("photo_b64"),
                }
        ALERTS = data.get("alerts", [])[-20:]
    except Exception:
        pass


def public_job(job):
    if not job:
        return None
    out = dict(job)
    out["progress"] = list(job.get("progress", []))[-20:]
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _text(self, text, status):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

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
        global LAST_SEEN
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/status":
            with LOCK:
                self._json({
                    "connected": connected(),
                    "pending": len(QUEUE),
                    "results": len(RESULTS),
                    "jobs": len(JOBS),
                })
            return
        ok, status, msg = check_key(self)
        if not ok:
            self._text(msg, status)
            return
        if path == "/pending":
            try:
                wait = float((query.get("wait") or ["0"])[0])
            except ValueError:
                wait = 0
            wait = max(0.0, min(25.0, wait))
            deadline = time.time() + wait
            command = None
            with COND:
                LAST_SEEN = time.time()
                while True:
                    if QUEUE:
                        jid = QUEUE.pop(0)
                        job = JOBS.get(jid)
                        if job is not None:
                            job["status"] = "running"
                            job["started_at"] = time.time()
                            command = {"id": job["id"], "text": job["text"]}
                            save_jobs()
                        break
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    COND.wait(timeout=remaining)
            self._json({"command": command})
            return
        if path == "/job":
            rid = (query.get("id") or [""])[0]
            with LOCK:
                job = JOBS.get(rid)
            if not job:
                self._text("job not found", 404)
                return
            self._json({"job": public_job(job)})
            return
        if path == "/jobs":
            with LOCK:
                jobs = [public_job(JOBS[jid]) for jid in list(JOBS.keys())[-50:]]
            self._json({"jobs": jobs})
            return
        if path == "/alerts":
            with LOCK:
                alerts = list(ALERTS[-20:])
            self._json({"alerts": alerts})
            return
        if path == "/result":
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
        parsed = urlparse(self.path)
        path = parsed.path
        ok, status, msg = check_key(self)
        if not ok:
            self._text(msg, status)
            return
        if path == "/command":
            body = self._read_json()
            if not body or not isinstance(body.get("id"), str) or not body["id"] \
                    or not isinstance(body.get("text"), str) or not body["text"]:
                self._text("id and text required", 400)
                return
            with COND:
                if body["id"] in JOBS:
                    self._json({"queued": False, "id": body["id"],
                                "error": "job id already exists"})
                    return
                job = {
                    "id": body["id"], "text": body["text"],
                    "status": "queued", "ok": None, "result": "",
                    "photo_b64": None, "progress": [],
                    "created_at": time.time(), "started_at": None,
                    "finished_at": None,
                }
                JOBS[body["id"]] = job
                QUEUE.append(body["id"])
                position = len(QUEUE)
                is_connected = connected()
                save_jobs()
                COND.notify()
            self._json({"queued": True, "id": body["id"],
                        "position": position, "connected": is_connected})
            return
        if path == "/result":
            body = self._read_json()
            if not body or not isinstance(body.get("id"), str) or not body["id"]:
                self._text("id required", 400)
                return
            with LOCK:
                job = JOBS.get(body["id"])
                if job is None:
                    job = {
                        "id": body["id"], "text": "", "status": "done",
                        "ok": bool(body.get("ok")), "result": "",
                        "photo_b64": None, "progress": [],
                        "created_at": time.time(), "started_at": None,
                        "finished_at": time.time(),
                    }
                    JOBS[body["id"]] = job
                was_cancelled = job.get("status") == "cancelled"
                if not was_cancelled:
                    job["status"] = "done" if body.get("ok") else "failed"
                    job["ok"] = bool(body.get("ok"))
                    job["finished_at"] = time.time()
                job["result"] = (body.get("text") or "")[:20000]
                job["photo_b64"] = body.get("photo_b64")
                result = {"type": "result", "id": job["id"],
                          "ok": job.get("ok", False),
                          "text": job["result"], "photo_b64": job["photo_b64"]}
                RESULTS[body["id"]] = result
                if not was_cancelled:
                    ALERTS.append({"id": job["id"], "ok": job.get("ok", False),
                                   "text": job["result"][:300],
                                   "time": time.time()})
                    del ALERTS[:-20]
                save_jobs()
            self._json({"ok": True})
            return
        if path == "/progress":
            body = self._read_json()
            if not body or not isinstance(body.get("id"), str) or not body["id"]:
                self._text("id required", 400)
                return
            with LOCK:
                job = JOBS.get(body["id"])
                if job is None:
                    self._text("job not found", 404)
                    return
                job.setdefault("progress", []).append({
                    "text": (body.get("text") or "")[:500],
                    "pct": body.get("pct"),
                    "time": time.time(),
                })
                job["progress"] = job["progress"][-20:]
                save_jobs()
            self._json({"ok": True})
            return
        if path == "/cancel":
            body = self._read_json()
            if not body or not isinstance(body.get("id"), str) or not body["id"]:
                self._text("id required", 400)
                return
            with LOCK:
                job = JOBS.get(body["id"])
                if job is None:
                    self._text("job not found", 404)
                    return
                if job["status"] == "queued" and body["id"] in QUEUE:
                    QUEUE.remove(body["id"])
                job["status"] = "cancelled"
                job["finished_at"] = time.time()
                save_jobs()
            self._json({"ok": True, "id": body["id"], "status": "cancelled"})
            return
        if path == "/cancel_all":
            body = self._read_json() or {}
            except_id = body.get("except_id", "")
            with LOCK:
                count = 0
                for jid in list(QUEUE):
                    if jid == except_id:
                        continue
                    job = JOBS.get(jid)
                    if job is not None:
                        job["status"] = "cancelled"
                        job["finished_at"] = time.time()
                        count += 1
                QUEUE[:] = [jid for jid in QUEUE if jid == except_id]
                for job in JOBS.values():
                    if job.get("status") == "running" and job["id"] != except_id:
                        job["status"] = "cancelled"
                        job["finished_at"] = time.time()
                        count += 1
                save_jobs()
            self._json({"ok": True, "cancelled": count})
            return
        self._text("not found", 404)


if __name__ == "__main__":
    with LOCK:
        load_jobs()
    port = int(os.environ.get("PORT", "8765"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("Relay-Own v2 server listening on port %d" % port, flush=True)
    print("RELAY_KEY set:", bool(os.environ.get("RELAY_KEY")), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
