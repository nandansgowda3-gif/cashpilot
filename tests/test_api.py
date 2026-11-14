import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from backend import server


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    """Tiny HTTP client that keeps one session cookie."""

    def __init__(self, base):
        self.base = base
        self.cookie = None
        self.opener = urllib.request.build_opener(NoRedirect)

    def call(self, method, path, body=None, csrf=True, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json"}
        if csrf:
            h["X-Requested-With"] = "cashpilot"
        if self.cookie:
            h["Cookie"] = self.cookie
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            r = self.opener.open(req)
        except urllib.error.HTTPError as e:
            r = e
        raw = r.read()
        sc = r.headers.get("Set-Cookie")
        if sc:
            pair = sc.split(";")[0]
            self.cookie = None if pair.endswith("=") else pair
        return r.status, raw, r.headers

    def json(self, *a, **k):
        code, raw, hdr = self.call(*a, **k)
        return code, (json.loads(raw) if raw else None)

    def login(self, user="demo", pw="Demo@1234"):
        return self.json("POST", "/api/login", {"username": user, "password": pw})


class AuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["CASHPILOT_QUIET"] = "1"
        for k in ("CASHPILOT_DEMO", "CASHPILOT_DEMO_USER", "CASHPILOT_DEMO_PASSWORD",
                  "CASHPILOT_ALLOW_SIGNUP", "CASHPILOT_SECURE_COOKIES", "CASHPILOT_TRUST_PROXY",
                  "DATABASE_URL", "VERCEL"):
            os.environ.pop(k, None)
        server.PBKDF2_ITERATIONS = 1000  # fast for tests; production uses 600,000
        cls.tmp = tempfile.TemporaryDirectory()
        server.DB_PATH = Path(cls.tmp.name) / "test.db"
        cls.httpd = server.make_server("127.0.0.1", 0)
        cls.base = "http://127.0.0.1:%d" % cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        server.LIMITER.reset()
        server.delete_bank_connection(server.find_user("demo")[0])
        self.c = Client(self.base)

    def signed_in(self, user="demo", pw="Demo@1234"):
        c = Client(self.base)
        self.assertEqual(c.login(user, pw)[0], 200)
        return c

    # ---- public bits -------------------------------------------------
    def test_health_is_public(self):
        self.assertEqual(self.c.json("GET", "/api/health"), (200, {"status": "ok"}))

    def test_wsgi_entrypoint_routes_api_and_static_requests(self):
        def call(path, method="GET", payload=None, headers=None):
            result = {}
            body = json.dumps(payload).encode() if payload is not None else b""

            def start_response(status, headers):
                result["status"] = status
                result["headers"] = dict(headers)

            body = b"".join(server.app({
                "REQUEST_METHOD": method,
                "PATH_INFO": path,
                "QUERY_STRING": "",
                "CONTENT_LENGTH": str(len(body)),
                "wsgi.input": io.BytesIO(body),
                "wsgi.url_scheme": "http",
                "SERVER_NAME": "localhost",
                "SERVER_PORT": "80",
                "REMOTE_ADDR": "127.0.0.1",
                **(headers or {}),
            }, start_response))
            return result, body

        result, body = call("/api/health")
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(json.loads(body), {"status": "ok"})

        result, _ = call("/")
        self.assertEqual(result["status"], "302 Found")
        self.assertEqual(result["headers"]["Location"], "/login")

        result, body = call("/login")
        self.assertEqual(result["status"], "200 OK")
        self.assertIn(b"login", body.lower())

        result, body = call(
            "/api/login",
            method="POST",
            payload={"username": "demo", "password": "Demo@1234"},
            headers={"HTTP_X_REQUESTED_WITH": "cashpilot"},
        )
        self.assertEqual(result["status"], "200 OK")
        self.assertIn("HttpOnly", result["headers"]["Set-Cookie"])

    def test_config_shows_demo_login(self):
        code, cfg = self.c.json("GET", "/api/config")
        self.assertEqual(code, 200)
        self.assertEqual(cfg["demo"], {"username": "demo", "password": "Demo@1234"})
        self.assertTrue(cfg["signup"])

    def test_login_page_is_public_and_app_redirects(self):
        self.assertEqual(self.c.call("GET", "/login")[0], 200)
        self.assertEqual(self.c.call("GET", "/login.js")[0], 200)
        code, _, hdr = self.c.call("GET", "/")
        self.assertEqual(code, 302)
        self.assertEqual(hdr["Location"], "/login")

    # ---- everything private needs a session ---------------------------
    def test_private_routes_need_login(self):
        for method, path in [("GET", "/api/state"), ("GET", "/api/export"), ("GET", "/api/me"),
                             ("GET", "/app.js"), ("GET", "/boot.js"), ("GET", "/index.html")]:
            code = self.c.call(method, path)[0]
            self.assertIn(code, (302, 401), path)
        self.assertEqual(self.c.call("PUT", "/api/state/cpl", {"value": "{}"})[0], 401)
        self.assertEqual(self.c.call("DELETE", "/api/state")[0], 401)

    def test_login_success_sets_safe_cookie(self):
        code, raw, hdr = self.c.call("POST", "/api/login", {"username": "demo", "password": "Demo@1234"})
        self.assertEqual(code, 200)
        cookie = hdr["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Path=/", cookie)
        self.assertEqual(self.c.json("GET", "/api/me")[1], {"username": "demo"})
        self.assertEqual(self.c.call("GET", "/")[0], 200)
        self.assertEqual(self.c.call("GET", "/app.js")[0], 200)
        self.assertEqual(self.c.call("GET", "/login")[0], 302)  # already signed in

    def test_username_is_case_insensitive(self):
        self.assertEqual(self.c.login("DEMO")[0], 200)

    def test_wrong_credentials_are_generic(self):
        a = self.c.login("demo", "wrong-password1")
        b = self.c.login("nobody", "wrong-password1")
        self.assertEqual(a[0], 401)
        self.assertEqual(a, b)  # same answer for a real and a made-up username
        self.assertIsNone(self.c.cookie)

    def test_login_rejects_bad_shapes(self):
        self.assertEqual(self.c.json("POST", "/api/login", {"username": 5, "password": "x"})[0], 400)
        self.assertEqual(self.c.json("POST", "/api/login", {})[0], 400)
        self.assertEqual(self.c.login("demo", "x" * 5000)[0], 413)

    def test_lockout_after_repeated_failures(self):
        for _ in range(5):
            self.assertEqual(self.c.login("demo", "bad-guess-1")[0], 401)
        code, body = self.c.login("demo", "Demo@1234")  # even the right password is refused for now
        self.assertEqual(code, 429)
        self.assertIn("Too many", body["error"])
        hdr = self.c.call("POST", "/api/login", {"username": "demo", "password": "Demo@1234"})[2]
        self.assertGreater(int(hdr["Retry-After"]), 0)

    def test_logout_ends_session_server_side(self):
        self.assertEqual(self.c.login()[0], 200)
        old = self.c.cookie
        self.assertEqual(self.c.json("POST", "/api/logout")[0], 200)
        self.assertIsNone(self.c.cookie)
        stale = Client(self.base)
        stale.cookie = old  # a stolen copy of the old cookie must no longer work
        self.assertEqual(stale.json("GET", "/api/me")[0], 401)

    def test_forged_and_garbage_cookies_rejected(self):
        for ck in ("cp_session=abc", "cp_session=" + "A" * 500, "cp_session=", "garbage"):
            c = Client(self.base)
            c.cookie = ck
            self.assertEqual(c.json("GET", "/api/me")[0], 401, ck)

    # ---- CSRF ---------------------------------------------------------
    def test_writes_need_csrf_header_and_same_origin(self):
        c = self.signed_in()
        self.assertEqual(c.call("PUT", "/api/state/cpl", {"value": "{}"}, csrf=False)[0], 403)
        self.assertEqual(c.call("DELETE", "/api/state", csrf=False)[0], 403)
        self.assertEqual(c.call("POST", "/api/logout", csrf=False)[0], 403)
        self.assertEqual(self.c.call("POST", "/api/login", {"username": "demo", "password": "Demo@1234"},
                                     csrf=False)[0], 403)
        evil = {"Origin": "https://evil.example"}
        self.assertEqual(c.call("PUT", "/api/state/cpl", {"value": "{}"}, headers=evil)[0], 403)
        self.assertEqual(c.json("GET", "/api/me")[0], 200)  # still signed in afterwards

    # ---- sign-up ------------------------------------------------------
    def test_register_validation(self):
        j = lambda u, p: self.c.json("POST", "/api/register", {"username": u, "password": p})
        self.assertEqual(j("ab", "Goodpass123")[0], 400)           # too short name
        self.assertEqual(j("bad name!", "Goodpass123")[0], 400)    # illegal characters
        self.assertEqual(j("newuser1", "short1")[0], 400)          # short password
        self.assertEqual(j("newuser1", "onlyletters")[0], 400)     # no digit
        self.assertEqual(j("newuser1", "password123")[0], 400)     # common
        self.assertEqual(j("newuser1", "newuser1")[0], 400)        # same as username
        self.assertEqual(j("demo", "Goodpass123")[0], 409)         # taken
        self.assertEqual(j("Demo", "Goodpass123")[0], 409)         # taken, any case

    def test_register_signs_in_and_data_is_private(self):
        alice = Client(self.base)
        code, body = alice.json("POST", "/api/register", {"username": "alice", "password": "Alice-pass-77"})
        self.assertEqual((code, body["username"]), (200, "alice"))
        self.assertEqual(alice.json("PUT", "/api/state/cpl", {"value": '{"Food":1}'})[0], 200)
        self.assertEqual(alice.json("GET", "/api/state")[1], {"cpl": '{"Food":1}'})
        demo = self.signed_in()
        self.assertNotIn("cpl", demo.json("GET", "/api/state")[1])   # demo can't see alice's data
        demo.json("PUT", "/api/state/cpl", {"value": "{}"})
        self.assertEqual(alice.json("GET", "/api/state")[1], {"cpl": '{"Food":1}'})
        self.assertEqual(demo.json("DELETE", "/api/state")[0], 200)  # clears only demo's data
        self.assertEqual(alice.json("GET", "/api/state")[1], {"cpl": '{"Food":1}'})
        self.assertEqual(alice.json("GET", "/api/export")[1]["state"], {"cpl": '{"Food":1}'})

    def test_passwords_and_tokens_are_not_stored_in_clear(self):
        c = self.signed_in()
        token = c.cookie.split("=", 1)[1]
        conn = sqlite3.connect(str(server.DB_PATH))
        try:
            hashes = [r[0] for r in conn.execute("SELECT pw_hash FROM users")]
            sessions = [r[0] for r in conn.execute("SELECT token_hash FROM sessions")]
        finally:
            conn.close()
        self.assertTrue(hashes and all(h.startswith("pbkdf2_sha256$") for h in hashes))
        self.assertFalse(any("Demo@1234" in h for h in hashes))
        self.assertNotIn(token, sessions)

    def test_password_hash_is_salted(self):
        a, b = server.hash_password("Same-pass-1"), server.hash_password("Same-pass-1")
        self.assertNotEqual(a, b)
        self.assertTrue(server.verify_password("Same-pass-1", a))
        self.assertFalse(server.verify_password("same-pass-1", a))
        self.assertFalse(server.verify_password("x", "garbage"))

    def test_expired_session_is_rejected(self):
        c = self.signed_in()
        conn = sqlite3.connect(str(server.DB_PATH))
        try:
            with conn:
                conn.execute("UPDATE sessions SET expires = 1")
        finally:
            conn.close()
        self.assertEqual(c.json("GET", "/api/me")[0], 401)

    # ---- app data + hardening ----------------------------------------------
    def test_state_roundtrip_and_clear(self):
        c = self.signed_in()
        c.json("DELETE", "/api/state")
        self.assertEqual(c.json("GET", "/api/state")[1], {})
        self.assertEqual(c.json("PUT", "/api/state/cpl", {"value": '{"Food":4000}'})[0], 200)
        self.assertEqual(c.json("GET", "/api/state")[1], {"cpl": '{"Food":4000}'})
        c.json("DELETE", "/api/state")
        self.assertEqual(c.json("GET", "/api/state")[1], {})

    def test_bank_routes_require_auth_csrf_and_valid_vua(self):
        self.assertEqual(self.c.json("GET", "/api/bank/status")[0], 401)
        self.assertEqual(self.c.json("GET", "/api/bank/transactions")[0], 401)
        c = self.signed_in()
        self.assertEqual(c.call("POST", "/api/bank/consent", {"vua": "9876543210"},
                                csrf=False)[0], 403)
        self.assertEqual(c.json("POST", "/api/bank/consent", {"vua": "not-a-number"})[0], 400)
        self.assertEqual(c.json("POST", "/api/bank/consent", 5)[0], 400)

    def test_bank_sandbox_flow_keeps_provider_data_minimal_and_revokes(self):
        consent_id = "12345678-1234-1234-1234-123456789012"
        session_id = "87654321-4321-4321-4321-210987654321"

        class FakeSetu:
            configured = True
            revoked = False

            def create_consent(self, vua, data_range):
                self.__class__.vua = vua
                self.__class__.data_range = data_range
                return {
                    "id": consent_id,
                    "url": "https://fiu-sandbox.setu.co/v2/consents/webview/" + consent_id,
                    "status": "PENDING",
                }

            def get_consent(self, current_id):
                return {"id": current_id, "status": "ACTIVE", "profile": {"name": "Private Name"}}

            def create_data_session(self, current_id, data_range):
                self.__class__.session_range = data_range
                return {"id": session_id, "status": "COMPLETED"}

            def get_data_session(self, current_id):
                return {
                    "status": "COMPLETED",
                    "data": {
                        "fips": [{
                            "accounts": [{
                                "maskedAccNumber": "XXXX1234",
                                "data": {
                                    "account": {"transactions": {"transaction": [{
                                        "amount": "1250.50",
                                        "type": "DEBIT",
                                        "transactionTimestamp": "2025-05-01T10:15:00Z",
                                        "narration": "MOCK MARKET",
                                        "txnId": "txn-1",
                                    }]}},
                                    "profile": {"name": "Private Name", "mobile": "9876543210"},
                                },
                            }],
                        }],
                    },
                }

            def revoke_consent(self, current_id):
                self.__class__.revoked = True
                return {"id": current_id, "status": "REVOKED"}

        c = self.signed_in()
        with mock.patch.object(server, "SetuAAClient", FakeSetu):
            code, created = c.json("POST", "/api/bank/consent", {"vua": "9876543210"})
            self.assertEqual(code, 201)
            self.assertEqual(created["consentStatus"], "PENDING")
            self.assertEqual(c.json("GET", "/api/bank/status")[1]["consentStatus"], "ACTIVE")
            self.assertEqual(c.json("POST", "/api/bank/sync")[0], 201)
            code, body = c.json("GET", "/api/bank/transactions")
            self.assertEqual(code, 200)
            self.assertEqual(body["sessionStatus"], "COMPLETED")
            self.assertEqual(body["transactions"], [{
                "id": "txn-1",
                "date": "2025-05-01",
                "description": "MOCK MARKET",
                "amount": "-1250.50",
                "maskedAccount": "XXXX1234",
            }])
            self.assertNotIn("Private Name", json.dumps(body))
            self.assertEqual(c.json("DELETE", "/api/bank/connection")[0], 200)
            self.assertTrue(FakeSetu.revoked)

        conn = sqlite3.connect(str(server.DB_PATH))
        try:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM bank_connections WHERE user_id = ?", (server.find_user("demo")[0],)
            ).fetchone())
        finally:
            conn.close()
        self.assertEqual(FakeSetu.vua, "9876543210")
        self.assertNotIn("9876543210", json.dumps(FakeSetu.data_range))

    def test_bank_status_reports_unconfigured_server_without_accepting_credentials(self):
        class UnconfiguredSetu:
            configured = False

        c = self.signed_in()
        with mock.patch.object(server, "SetuAAClient", UnconfiguredSetu):
            self.assertEqual(c.json("GET", "/api/bank/status"),
                             (200, {"configured": False, "mode": "sandbox"}))
            self.assertEqual(c.json("POST", "/api/bank/consent", {"vua": "9876543210"})[0], 503)

    def test_bank_consent_rejects_non_setu_consent_urls(self):
        class InvalidUrlSetu:
            configured = True

            def create_consent(self, vua, data_range):
                return {
                    "id": "12345678-1234-1234-1234-123456789012",
                    "url": "https://attacker.example/consent",
                    "status": "PENDING",
                }

        c = self.signed_in()
        with mock.patch.object(server, "SetuAAClient", InvalidUrlSetu):
            self.assertEqual(c.json("POST", "/api/bank/consent",
                                    {"vua": "9876543210"})[0], 502)
        self.assertIsNone(server.get_bank_connection(server.find_user("demo")[0]))

    def test_rejects_bad_input(self):
        c = self.signed_in()
        self.assertEqual(c.json("PUT", "/api/state/evil", {"value": "x"})[0], 400)
        self.assertEqual(c.json("PUT", "/api/state/cpl", {"value": 5})[0], 400)
        self.assertEqual(c.json("GET", "/api/nope")[0], 404)

    def test_security_headers(self):
        _, _, hdr = self.c.call("GET", "/login")
        self.assertEqual(hdr["X-Content-Type-Options"], "nosniff")
        self.assertEqual(hdr["X-Frame-Options"], "DENY")
        self.assertEqual(hdr["Referrer-Policy"], "no-referrer")
        self.assertEqual(hdr["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", hdr["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", hdr["Content-Security-Policy"].split("style-src")[0])
        self.assertNotIn("Strict-Transport-Security", hdr)  # plain http locally

    def test_secure_flag_and_hsts_when_behind_https(self):
        os.environ["CASHPILOT_SECURE_COOKIES"] = "1"
        try:
            _, _, hdr = self.c.call("POST", "/api/login", {"username": "demo", "password": "Demo@1234"})
            self.assertIn("Secure", hdr["Set-Cookie"])
            self.assertIn("Strict-Transport-Security", hdr)
        finally:
            del os.environ["CASHPILOT_SECURE_COOKIES"]

    def test_signup_can_be_disabled(self):
        os.environ["CASHPILOT_ALLOW_SIGNUP"] = "0"
        try:
            self.assertEqual(self.c.json("POST", "/api/register",
                                         {"username": "carol", "password": "Carol-pass-9"})[0], 403)
        finally:
            del os.environ["CASHPILOT_ALLOW_SIGNUP"]

    def test_vercel_requires_persistent_database(self):
        os.environ["VERCEL"] = "1"
        try:
            self.assertFalse(server.demo_enabled())
            self.assertTrue(server.secure_cookies())
            with self.assertRaisesRegex(RuntimeError, "DATABASE_URL"):
                server._connect()
        finally:
            del os.environ["VERCEL"]

    def test_no_path_traversal(self):
        c = self.signed_in()
        self.assertEqual(c.call("GET", "/../run.py")[0], 404)
        self.assertEqual(c.call("GET", "/%2e%2e/run.py")[0], 404)
        self.assertEqual(c.call("GET", "/..%2fdata/test.db")[0], 404)


if __name__ == "__main__":
    unittest.main()
