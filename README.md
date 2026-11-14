# CashPilot

Predictive cash-flow app (Build Beyond'26, PS 2.2): forecasts your balance, warns before money runs short, lets you set monthly limits, learns from its own forecast misses, and has a built-in assistant. Sign-in required.

## Run it (VS Code or any terminal)

Needs Python 3.8 or newer. Nothing to install.

```
python run.py          # Windows: py run.py     macOS/Linux: python3 run.py
```

Then open http://localhost:8000 and sign in.

**Demo account:** username `demo`, password `Demo@1234` (the login page has a "Sign in as demo" button). Or use "Create account" to make your own. Every account has its own private data.

In VS Code: open this folder, press **F5** (config "Run CashPilot"), or run the command above in the terminal.

Port busy? `PORT=8001 python run.py` (Windows PowerShell: `$env:PORT=8001; python run.py`).

## Run the tests

```
python -m unittest discover -s tests -t . -v
```

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `PORT`, `HOST` | `8000`, `127.0.0.1` | where to listen |
| `CASHPILOT_DEMO` | `1` | `0` removes the demo-login box (the demo user is not created) |
| `CASHPILOT_DEMO_USER`, `CASHPILOT_DEMO_PASSWORD` | `demo`, `Demo@1234` | change the demo credentials |
| `CASHPILOT_ALLOW_SIGNUP` | `1` | `0` turns off "Create account" |
| `CASHPILOT_SECURE_COOKIES` | `0` | `1` when served over HTTPS: adds the `Secure` cookie flag and HSTS |
| `CASHPILOT_TRUST_PROXY` | `0` | `1` behind a reverse proxy that sets `X-Forwarded-Proto` / `X-Forwarded-For` |
| `CASHPILOT_DB` | `data/cashpilot.db` | database file location |

## How the sign-in is secured

- **Passwords** are never stored. Each is salted and stretched with PBKDF2-HMAC-SHA256 (600,000 rounds) and compared in constant time. Unknown usernames take as long to reject as wrong passwords, and both give the same message.
- **Sessions** use a random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie, so page scripts cannot read it and other sites cannot send it. Only a hash of the token is kept on the server. Logging out deletes the session on the server. Sessions end after 8 idle hours, or 7 days at most.
- **CSRF**: every change needs an `X-Requested-With` header and a matching `Origin`, on top of `SameSite=Strict`.
- **Brute force**: 5 failed sign-ins for a username (or 20 from one IP address) block further attempts for 15 minutes. Sign-up is limited to 10 accounts per IP per hour.
- **Passwords you choose** need 8 to 128 characters, with letters and numbers, and not a very common password or your username.
- **Data isolation**: every read and write is tied to the signed-in user. The dashboard files themselves are only served after sign-in.
- **Headers**: Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, no-referrer, `no-store` caching.
- The browser's cached copy of your data is wiped on log out and whenever a different user signs in on the same browser.

## Before putting it on the internet

1. Put it behind HTTPS (Caddy, nginx, a host's built-in TLS), then set `CASHPILOT_SECURE_COOKIES=1` (and `CASHPILOT_TRUST_PROXY=1` if the proxy sets the forwarded headers).
2. Set `CASHPILOT_DEMO=0` unless you want a public demo account. Its password is shown on the login page on purpose, and everyone who uses it shares the same data.
3. Keep `data/cashpilot.db` out of any public folder and back it up.

Known limits: the dashboard builds its buttons with inline handlers, so its policy has to allow inline scripts (the login page is strict). Failed-attempt counters live in memory and reset when the server restarts. There is no password reset by email; the database owner can delete an account. Data saved by the earlier single-user version stays in the old table and is not shown to any account.

## How it fits together

- `frontend/login.html` (+ `login.js`, `login.css`) is the sign-in page. `index.html` is the app (plain HTML and JavaScript). `boot.js` checks you are signed in, loads your saved data from the backend, then starts `app.js`.
- `backend/server.py` serves the frontend and stores users, sessions and app data in `data/cashpilot.db` (SQLite). API: `POST /api/login`, `/api/register`, `/api/logout`; `GET /api/me`, `/api/config`, `/api/health`, `/api/state`, `/api/export`; `PUT /api/state/<key>`; `DELETE /api/state`.
- Opening `frontend/index.html` directly from disk still works for a quick look, with no sign-in: it uses the browser's own storage instead of the backend.

## Notes

- Money tab: tap a spending category (or "Edit received money") to change totals, amounts, descriptions and categories, or delete items.
- "Connect bank (demo)" only simulates transactions.
- The assistant (robot button) understands a fixed set of phrases; type `help` to see them.
