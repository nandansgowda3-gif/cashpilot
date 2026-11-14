#!/usr/bin/env python3
"""CashPilot backend.

Serves the frontend and keeps each user's data in a small SQLite file.
Sign-in is required. Standard library only: nothing to install.

Run from the project root:   python run.py      (or python3 run.py)

Security model (see README for the full list):
  * Passwords are salted and stretched with PBKDF2-HMAC-SHA256 (600,000 rounds).
  * Sessions are random 256-bit tokens kept in an HttpOnly, SameSite=Strict cookie;
    only a SHA-256 hash of the token is stored on the server.
  * Every write needs a custom header plus a matching Origin (CSRF defence).
  * Failed sign-ins are rate limited per username and per IP address.
  * Every user can only ever read or change their own data.
"""
import base64
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from email.message import Message
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
DB_PATH = Path(os.environ.get("CASHPILOT_DB") or (ROOT / "data" / "cashpilot.db"))
_postgres_schema_ready = False

# Keys the frontend stores (transactions, overrides, limits, learning, notes).
ALLOWED_KEYS = {"cp2", "cpo", "cpl", "cph", "cpm", "cpf", "cpn"}
MAX_BODY = 5 * 1024 * 1024  # 5 MB for app data
MAX_AUTH_BODY = 4 * 1024    # sign-in / sign-up bodies are tiny

COOKIE = "cp_session"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "cashpilot"

PBKDF2_ITERATIONS = 600000
SESSION_IDLE = 8 * 3600       # signed out after 8 hours without use
SESSION_MAX = 7 * 86400       # and never later than 7 days after sign-in

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD, MAX_PASSWORD = 8, 128
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789", "1234567890",
    "qwerty123", "qwertyuiop", "iloveyou", "admin123", "welcome1", "letmein123",
    "11111111", "abc12345", "cashpilot", "cashpilot1", "cashpilot123",
}

# Public pages: everything else needs a valid session.
PUBLIC_FILES = {"login.html", "login.js", "login.css"}

CSP_API = "default-src 'none'; frame-ancestors 'none'"
CSP_LOGIN = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
             "img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
# The dashboard builds its buttons with inline handlers, so it needs 'unsafe-inline' for scripts.
CSP_APP = ("default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
           "connect-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; "
           "frame-ancestors 'none'")

_lock = threading.Lock()


# ---- settings (read at call time so they can be changed per run) ---------
def _flag(name, default):
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def demo_enabled():
    return _flag("CASHPILOT_DEMO", not bool(os.environ.get("VERCEL")))


def demo_user():
    return os.environ.get("CASHPILOT_DEMO_USER") or "demo"


def demo_password():
    return os.environ.get("CASHPILOT_DEMO_PASSWORD") or "Demo@1234"


def signup_allowed():
    return _flag("CASHPILOT_ALLOW_SIGNUP", True)


def secure_cookies():
    return _flag("CASHPILOT_SECURE_COOKIES", bool(os.environ.get("VERCEL")))


def trust_proxy():
    return _flag("CASHPILOT_TRUST_PROXY", False)


# ---- database -------------------------------------------------------------
class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, params=()):
        return self.connection.execute(query.replace("?", "%s"), params)

    def close(self):
        self.connection.close()

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self.connection.__exit__(exc_type, exc_value, traceback)


def _connect():
    global _postgres_schema_ready
    database_url = os.environ.get("DATABASE_URL")
    if os.environ.get("VERCEL") and not database_url:
        raise RuntimeError("DATABASE_URL must point to a persistent PostgreSQL database on Vercel.")
    if database_url:
        import psycopg

        conn = psycopg.connect(database_url, connect_timeout=10)
        if not _postgres_schema_ready:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                " id BIGSERIAL PRIMARY KEY,"
                " username TEXT NOT NULL,"
                " pw_hash TEXT NOT NULL,"
                " created TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username))")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS user_state ("
                " user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
                " key TEXT NOT NULL, value TEXT NOT NULL,"
                " updated TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                " PRIMARY KEY (user_id, key))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions ("
                " token_hash TEXT PRIMARY KEY,"
                " user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
                " created DOUBLE PRECISION NOT NULL, expires DOUBLE PRECISION NOT NULL)"
            )
            conn.commit()
            _postgres_schema_ready = True
        return PostgresConnection(conn)

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    fresh = not DB_PATH.exists()
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS users ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
        " pw_hash TEXT NOT NULL,"
        " created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
        "CREATE TABLE IF NOT EXISTS user_state ("
        " user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " key TEXT NOT NULL, value TEXT NOT NULL,"
        " updated TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        " PRIMARY KEY (user_id, key));"
        "CREATE TABLE IF NOT EXISTS sessions ("
        " token_hash TEXT PRIMARY KEY,"
        " user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " created REAL NOT NULL, expires REAL NOT NULL);"
    )
    if fresh:
        try:
            os.chmod(str(DB_PATH), 0o600)  # owner only (ignored on Windows)
        except OSError:
            pass
    return conn


def _db(fn):
    with _lock:
        conn = _connect()
        try:
            with conn:
                return fn(conn)
        finally:
            conn.close()


# ---- passwords ------------------------------------------------------------
def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def hash_password(password, iterations=None):
    iterations = iterations or PBKDF2_ITERATIONS
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, _b64(salt), _b64(dk))


def verify_password(password, stored):
    try:
        algo, iters, salt, expected = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 base64.b64decode(salt), int(iters))
        return hmac.compare_digest(_b64(dk), expected)
    except (ValueError, TypeError):
        return False


_dummy_hash = None


def burn_time(password):
    """Spend the same time as a real check so unknown usernames can't be told apart."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_hex(8))
    verify_password(password, _dummy_hash)


def password_problem(username, password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        return "Password must be at least %d characters." % MIN_PASSWORD
    if len(password) > MAX_PASSWORD:
        return "Password must be at most %d characters." % MAX_PASSWORD
    if password.lower() == username.lower() or password.lower() in COMMON_PASSWORDS:
        return "That password is too easy to guess. Pick something less common."
    if not (re.search(r"[A-Za-z]", password) and re.search(r"[0-9]", password)):
        return "Use both letters and numbers in your password."
    return None


# ---- users and sessions -----------------------------------------------------
def find_user(username):
    return _db(lambda c: c.execute(
        "SELECT id, username, pw_hash FROM users WHERE lower(username) = lower(?)", (username,)).fetchone())


def add_user(username, password):
    """Returns the new user id, or None if the username is taken."""
    pw = hash_password(password)  # slow on purpose; done outside the DB lock

    def f(c):
        if isinstance(c, PostgresConnection):
            import psycopg
            try:
                return c.execute(
                    "INSERT INTO users (username, pw_hash) VALUES (?, ?) RETURNING id",
                    (username, pw)).fetchone()[0]
            except psycopg.IntegrityError:
                return None
        try:
            return c.execute("INSERT INTO users (username, pw_hash) VALUES (?, ?)",
                             (username, pw)).lastrowid
        except sqlite3.IntegrityError:
            return None
    return _db(f)


def ensure_demo():
    if not demo_enabled():
        return
    name, pw = demo_user(), demo_password()
    row = find_user(name)
    if row is None:
        add_user(name, pw)
    elif not verify_password(pw, row[2]):  # keep the demo password in step with the setting
        new = hash_password(pw)
        _db(lambda c: c.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (new, row[0])))


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()

    def f(c):
        c.execute("DELETE FROM sessions WHERE expires < ? OR created < ?", (now, now - SESSION_MAX))
        c.execute("INSERT INTO sessions (token_hash, user_id, created, expires) VALUES (?, ?, ?, ?)",
                  (_token_hash(token), user_id, now, now + SESSION_IDLE))
    _db(f)
    return token


def session_user(token):
    """(user_id, username) for a valid session, else None. Extends the idle timer."""
    if not token or len(token) > 100:
        return None
    th, now = _token_hash(token), time.time()

    def f(c):
        r = c.execute(
            "SELECT s.created, s.expires, u.id, u.username FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?", (th,)).fetchone()
        if not r:
            return None
        created, expires, uid, uname = r
        if now >= expires or now >= created + SESSION_MAX:
            c.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
            return None
        new = min(now + SESSION_IDLE, created + SESSION_MAX)
        if new - expires > 60:
            c.execute("UPDATE sessions SET expires = ? WHERE token_hash = ?", (new, th))
        return uid, uname
    return _db(f)


def delete_session(token):
    if token:
        _db(lambda c: c.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),)))


# ---- per-user app data ------------------------------------------------------
def get_all(uid):
    return _db(lambda c: {k: v for k, v in c.execute(
        "SELECT key, value FROM user_state WHERE user_id = ?", (uid,))})


def put_key(uid, key, value):
    _db(lambda c: c.execute(
        "INSERT INTO user_state (user_id, key, value, updated) VALUES (?, ?, ?, CURRENT_TIMESTAMP) "
        "ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated = CURRENT_TIMESTAMP",
        (uid, key, value)))


def clear_all(uid):
    _db(lambda c: c.execute("DELETE FROM user_state WHERE user_id = ?", (uid,)))


# ---- rate limiting ----------------------------------------------------------
class Limiter:
    """Remembers recent failures in memory (resets when the server restarts)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.hits = {}

    def retry_after(self, rules):
        """rules: [(key, limit, window_seconds)]. Seconds to wait, or 0 if allowed."""
        now, wait = time.time(), 0
        with self.lock:
            for key, limit, window in rules:
                recent = [t for t in self.hits.get(key, []) if now - t < window]
                self.hits[key] = recent
                if len(recent) >= limit:
                    wait = max(wait, int(window - (now - recent[0])) + 1)
        return wait

    def add(self, *keys):
        now = time.time()
        with self.lock:
            if len(self.hits) > 5000:  # stay small under a flood
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < 3600}
            for k in keys:
                self.hits.setdefault(k, []).append(now)

    def clear(self, key):
        with self.lock:
            self.hits.pop(key, None)

    def reset(self):
        with self.lock:
            self.hits.clear()


LIMITER = Limiter()
LOGIN_WINDOW = 15 * 60


class Handler(BaseHTTPRequestHandler):
    server_version = "CashPilot/2.0"
    sys_version = ""

    # ---- helpers -------------------------------------------------------
    def _https(self):
        if secure_cookies():
            return True
        return trust_proxy() and self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _ip(self):
        if trust_proxy():
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[-1].strip()[:64]
        return self.client_address[0]

    def _send(self, code, body, ctype="application/json", csp=CSP_API, headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if self._https():
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, code, message, headers=None):
        self._send(code, {"error": message}, headers=headers)

    def _redirect(self, location):
        self._send(302, b"", "text/plain", headers=[("Location", location)])

    def _cookie_header(self, token):
        parts = ["%s=%s" % (COOKIE, token if token else ""), "Path=/", "HttpOnly", "SameSite=Strict"]
        if not token:
            parts.append("Max-Age=0")
        if self._https():
            parts.append("Secure")
        return ("Set-Cookie", "; ".join(parts))

    def _token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = SimpleCookie()
            jar.load(raw)
        except Exception:
            return None
        m = jar.get(COOKIE)
        return m.value if m else None

    def _auth(self):
        res = session_user(self._token())
        return res  # (user_id, username) or None

    def _csrf_ok(self):
        if self.headers.get(CSRF_HEADER) != CSRF_VALUE:
            return False
        origin = self.headers.get("Origin")
        if origin is not None:
            host = self.headers.get("Host", "")
            if urlparse(origin).netloc != host:
                return False
        return True

    def _json_body(self, limit):
        """Parsed JSON object, or None after sending an error."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(400, "Bad Content-Length")
            return None
        if length <= 0 or length > limit:
            self._error(413 if length > limit else 400, "Body missing or too large")
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._error(400, "Body must be JSON")
            return None
        if not isinstance(data, dict):
            self._error(400, "Body must be a JSON object")
            return None
        return data

    def _key_from_path(self, path):
        prefix = "/api/state/"
        if not path.startswith(prefix):
            return None
        key = unquote(path[len(prefix):])
        return key if key in ALLOWED_KEYS else ""

    def log_message(self, fmt, *args):  # quieter console
        if os.environ.get("CASHPILOT_QUIET") != "1":
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- routes --------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            return self._send(200, {"status": "ok"})
        if path == "/api/config":
            demo = {"username": demo_user(), "password": demo_password()} if demo_enabled() else None
            return self._send(200, {"signup": signup_allowed(), "demo": demo})
        if path == "/api/me":
            who = self._auth()
            if not who:
                return self._error(401, "Not signed in")
            return self._send(200, {"username": who[1]})
        if path in ("/api/state", "/api/export"):
            who = self._auth()
            if not who:
                return self._error(401, "Not signed in")
            state = get_all(who[0])
            return self._send(200, state if path == "/api/state" else {"app": "cashpilot", "state": state})
        if path.startswith("/api/"):
            return self._error(404, "Unknown API route")
        self._static(path)

    do_HEAD = do_GET

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/login", "/api/register", "/api/logout"):
            return self._error(404, "Unknown API route")
        if not self._csrf_ok():
            return self._error(403, "Request blocked")
        if path == "/api/logout":
            delete_session(self._token())
            return self._send(200, {"ok": True}, headers=[self._cookie_header(None)])
        data = self._json_body(MAX_AUTH_BODY)
        if data is None:
            return
        if path == "/api/login":
            return self._login(data)
        return self._register(data)

    def _login(self, data):
        username, password = data.get("username"), data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return self._error(400, "Enter a username and password.")
        username = username.strip()
        ukey, ipkey = "u:" + username.lower()[:64], "ip:" + self._ip()
        wait = LIMITER.retry_after([(ukey, 5, LOGIN_WINDOW), (ipkey, 20, LOGIN_WINDOW)])
        if wait:
            return self._error(429, "Too many failed attempts. Try again in %d minutes." % (wait // 60 + 1),
                               headers=[("Retry-After", str(wait))])
        row = find_user(username) if (USERNAME_RE.match(username) and len(password) <= MAX_PASSWORD) else None
        ok = bool(row) and verify_password(password, row[2])
        if not row:
            burn_time(password[:MAX_PASSWORD])
        if not ok:
            LIMITER.add(ukey, ipkey)
            return self._error(401, "Incorrect username or password.")
        LIMITER.clear(ukey)
        token = create_session(row[0])
        self._send(200, {"ok": True, "username": row[1]}, headers=[self._cookie_header(token)])

    def _register(self, data):
        if not signup_allowed():
            return self._error(403, "Sign-up is turned off on this server.")
        username, password = data.get("username"), data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return self._error(400, "Enter a username and password.")
        username = username.strip()
        if not USERNAME_RE.match(username):
            return self._error(400, "Username must be 3-32 characters: letters, numbers, . _ -")
        problem = password_problem(username, password)
        if problem:
            return self._error(400, problem)
        rkey = "reg:" + self._ip()
        if LIMITER.retry_after([(rkey, 10, 3600)]):
            return self._error(429, "Too many new accounts from this address. Try again later.")
        uid = add_user(username, password)
        if uid is None:
            return self._error(409, "That username is taken.")
        LIMITER.add(rkey)
        token = create_session(uid)
        self._send(200, {"ok": True, "username": username}, headers=[self._cookie_header(token)])

    def do_PUT(self):
        path = urlparse(self.path).path
        key = self._key_from_path(path)
        if key is None:
            return self._error(404, "Unknown API route")
        who = self._auth()
        if not who:
            return self._error(401, "Not signed in")
        if not self._csrf_ok():
            return self._error(403, "Request blocked")
        if key == "":
            return self._error(400, "Key not allowed")
        payload = self._json_body(MAX_BODY)
        if payload is None:
            return
        value = payload.get("value")
        if not isinstance(value, str):
            return self._error(400, 'Body must look like {"value": "<string>"}')
        put_key(who[0], key, value)
        self._send(200, {"ok": True})

    def do_DELETE(self):
        if urlparse(self.path).path != "/api/state":
            return self._error(404, "Unknown API route")
        who = self._auth()
        if not who:
            return self._error(401, "Not signed in")
        if not self._csrf_ok():
            return self._error(403, "Request blocked")
        clear_all(who[0])
        self._send(200, {"ok": True})

    def _static(self, path):
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        if rel == "login":
            rel = "login.html"
        who = self._auth()
        if rel == "login.html" and who:
            return self._redirect("/")
        if rel not in PUBLIC_FILES and not who:
            if rel == "index.html":
                return self._redirect("/login")
            return self._error(401, "Not signed in")
        target = (FRONTEND / unquote(rel)).resolve()
        try:
            target.relative_to(FRONTEND.resolve())
        except ValueError:
            return self._error(404, "Not found")
        if not target.is_file():
            return self._error(404, "Not found")
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        csp = CSP_LOGIN if rel in PUBLIC_FILES else CSP_APP
        self._send(200, target.read_bytes(), ctype, csp=csp)


class _WSGIHandler(Handler):
    def send_response(self, code, message=None):
        del message
        self._response_status = code
        self._response_headers = []

    def send_header(self, keyword, value):
        self._response_headers.append((keyword, value))

    def end_headers(self):
        pass


def app(environ, start_response):
    _connect().close()
    ensure_demo()

    request = _WSGIHandler.__new__(_WSGIHandler)
    request.command = environ.get("REQUEST_METHOD", "GET").upper()
    request.path = environ.get("PATH_INFO") or "/"
    query = environ.get("QUERY_STRING", "")
    if query:
        request.path += "?" + query
    request.requestline = "%s %s" % (request.command, request.path)
    request.headers = Message()
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            request.headers[key[5:].replace("_", "-")] = value
    request.headers["Content-Length"] = environ.get("CONTENT_LENGTH") or "0"
    if environ.get("CONTENT_TYPE"):
        request.headers["Content-Type"] = environ["CONTENT_TYPE"]
    if not request.headers.get("Host"):
        scheme = environ.get("wsgi.url_scheme", "http")
        default_port = "443" if scheme == "https" else "80"
        host = environ.get("SERVER_NAME", "localhost")
        port = environ.get("SERVER_PORT", default_port)
        request.headers["Host"] = host if port == default_port else "%s:%s" % (host, port)
    request.client_address = (environ.get("REMOTE_ADDR", ""), 0)
    request.rfile = environ["wsgi.input"]
    request.wfile = io.BytesIO()
    request._response_status = 200
    request._response_headers = []

    method = getattr(request, "do_" + request.command, None)
    if method is None:
        request._error(501, "Unsupported method")
    else:
        method()

    status = HTTPStatus(request._response_status)
    start_response(
        "%d %s" % (status.value, status.phrase),
        [(name, str(value)) for name, value in request._response_headers],
    )
    return [request.wfile.getvalue()]


def make_server(host="127.0.0.1", port=8000):
    _connect().close()  # create tables
    ensure_demo()
    return ThreadingHTTPServer((host, port), Handler)


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError:
        print("PORT must be a number, for example: PORT=8001")
        return 1
    try:
        httpd = make_server(host, port)
    except OSError as exc:
        print("Could not start on %s:%s (%s)." % (host, port, exc))
        print("Try another port, e.g. PORT=8001 python run.py")
        return 1
    print("CashPilot running at http://%s:%s  (Ctrl+C to stop)" % (
        "localhost" if host in ("127.0.0.1", "0.0.0.0") else host, port))
    print("Data file:", DB_PATH)
    if demo_enabled():
        print("Demo login:  %s / %s   (public on purpose; CASHPILOT_DEMO=0 turns it off)" % (
            demo_user(), demo_password()))
    if host not in ("127.0.0.1", "localhost", "::1") and not (secure_cookies() or trust_proxy()):
        print("WARNING: listening beyond this computer without HTTPS settings. Put it behind HTTPS and set "
              "CASHPILOT_SECURE_COOKIES=1 (see README).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
