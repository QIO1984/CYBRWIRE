"""
Serve CybrWire in a browser (needs the "web" extra: pip install "cybrwire[web]").

The page is a terminal in the browser. It is protected by a sign-in page (a cookie is kept for 30 days):
set CYBRWIRE_WEB_PASSWORD (and optionally CYBRWIRE_WEB_USER, default "cybrwire"). On localhost
the password is optional; on any other address the server refuses to start without one.

The password travels unencrypted over plain http, so keep it to your LAN or Tailscale (which
encrypts), or put an https proxy in front.

Other settings: CYBRWIRE_WEB_HOST (default 127.0.0.1), CYBRWIRE_WEB_PORT (8000) and
CYBRWIRE_WEB_URL (the address your browser uses, if not http://HOST:PORT).
"""

import asyncio
import base64
import hmac
import html
import os
import sys
import time
from urllib.parse import parse_qs

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def credentials_ok(header: str | None, user: str, password: str) -> bool:
    """True if an Authorization header carries the right user and password."""
    if not header or not header.lower().startswith("basic "):
        return False
    try:
        given = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    given_user, sep, given_pass = given.partition(":")
    # Check both parts every time, in constant time, so timing reveals nothing.
    user_ok = hmac.compare_digest(given_user.encode(), user.encode())
    pass_ok = hmac.compare_digest(given_pass.encode(), password.encode())
    return bool(sep) and user_ok and pass_ok


def check_config(host: str, password: str) -> str | None:
    """Return an error message if this host/password combination is unsafe, else None."""
    if not password and host not in LOCAL_HOSTS:
        return (f"Refusing to serve on {host} without a password. "
                "Set CYBRWIRE_WEB_PASSWORD (or use CYBRWIRE_WEB_HOST=127.0.0.1).")
    return None


COOKIE = "cybrwire_session"
SESSION_SECONDS = 30 * 24 * 3600

LOGIN_PAGE = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CybrWire</title>
<style>
html,body{{height:100%;margin:0;background:#0b0b14;color:#e6e6f0;font:16px ui-monospace,Menlo,Consolas,monospace}}
form{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:min(320px,86vw);display:grid;gap:14px}}
h1{{margin:0 0 4px;font-size:22px;letter-spacing:.2em;color:#ff4fd8}}
input,button{{font:inherit;padding:10px 12px;border-radius:6px;border:1px solid #3a3a5c;background:#14142a;color:inherit}}
input:focus{{outline:none;border-color:#00e5ff}}
button{{background:#ff4fd8;color:#0b0b14;border:0;font-weight:700;cursor:pointer}}
.err{{color:#ff6b6b;font-size:14px;min-height:1em}}
</style>
<form method="post" action="/login">
<h1>CYBRWIRE</h1>
<input type="hidden" name="user" value="{user}">
<input type="password" name="password" placeholder="Password" autocomplete="current-password" autofocus required>
<div class="err">{error}</div>
<button type="submit">Sign in</button>
</form>"""


def session_token(user: str, password: str, expires: int) -> str:
    sig = hmac.new(password.encode(), f"{user}|{expires}".encode(), "sha256").hexdigest()
    return f"{expires}.{sig}"


def token_ok(token: str | None, user: str, password: str, now: float | None = None) -> bool:
    if not token or "." not in token:
        return False
    expires, _, _ = token.partition(".")
    if not expires.isdigit() or int(expires) < (now if now is not None else time.time()):
        return False
    return hmac.compare_digest(token.encode(), session_token(user, password, int(expires)).encode())


def make_auth_middleware(user: str, password: str):
    from aiohttp import web

    def login_page(error: str = "", status: int = 200):
        return web.Response(status=status, content_type="text/html",
                            text=LOGIN_PAGE.format(user=html.escape(user), error=html.escape(error)),
                            headers={"Cache-Control": "no-store"})

    @web.middleware
    async def auth(request, handler):
        if request.path == "/login" and request.method == "POST":
            form = parse_qs((await request.read()).decode("utf-8", "replace"))
            given_user = (form.get("user") or [user])[0]
            given_pass = (form.get("password") or [""])[0]
            ok = hmac.compare_digest(given_user.encode(), user.encode()) & \
                hmac.compare_digest(given_pass.encode(), password.encode())
            if not ok:
                await asyncio.sleep(1)  # slows down password guessing
                return login_page("Wrong password", 401)
            resp = web.HTTPSeeOther("/")
            resp.set_cookie(COOKIE, session_token(user, password, int(time.time()) + SESSION_SECONDS),
                            max_age=SESSION_SECONDS, httponly=True, samesite="Strict")
            return resp
        if token_ok(request.cookies.get(COOKIE), user, password) or \
                credentials_ok(request.headers.get("Authorization"), user, password):
            if request.path == "/login":
                raise web.HTTPSeeOther("/")
            return await handler(request)
        if request.method == "GET" and request.path in ("/", "/login"):
            return login_page()
        return web.Response(status=401, text="Sign in at /")
    return auth


def main() -> None:
    try:
        from textual_serve.server import Server
    except ImportError:
        sys.exit('The browser version needs an extra package: pip install "cybrwire[web]"')

    host = os.environ.get("CYBRWIRE_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("CYBRWIRE_WEB_PORT", "8000"))
    user = os.environ.get("CYBRWIRE_WEB_USER", "cybrwire")
    password = os.environ.get("CYBRWIRE_WEB_PASSWORD", "")
    problem = check_config(host, password)
    if problem:
        sys.exit(problem)

    class AuthServer(Server):
        async def _make_app(self):
            app = await super()._make_app()
            if password:
                app.middlewares.append(make_auth_middleware(user, password))
            return app

    AuthServer(f'"{sys.executable}" -m cybrwire', host=host, port=port, title="CybrWire",
               public_url=os.environ.get("CYBRWIRE_WEB_URL") or None).serve()


if __name__ == "__main__":
    main()
