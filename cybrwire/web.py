"""
Serve CybrWire in a browser (needs the "web" extra: pip install "cybrwire[web]").

The page is a terminal in the browser. It is protected by a sign-in box (HTTP Basic auth):
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
import os
import sys

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


def make_auth_middleware(user: str, password: str):
    from aiohttp import web

    @web.middleware
    async def auth(request, handler):
        if credentials_ok(request.headers.get("Authorization"), user, password):
            return await handler(request)
        await asyncio.sleep(1)  # slows down password guessing
        return web.Response(status=401, text="Sign in to CybrWire",
                            headers={"WWW-Authenticate": 'Basic realm="CybrWire", charset="UTF-8"'})
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
