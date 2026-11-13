"""
Serve CybrWire in a browser (needs the "web" extra: pip install "cybrwire[web]").

The page is a terminal in the browser; it has no login of its own. Keep it on localhost, or
behind something you trust such as Tailscale. Settings: CYBRWIRE_WEB_HOST (default 127.0.0.1),
CYBRWIRE_WEB_PORT (8000) and CYBRWIRE_WEB_URL (the address your browser uses, if not http://HOST:PORT).
"""

import os
import sys


def main() -> None:
    try:
        from textual_serve.server import Server
    except ImportError:
        sys.exit('The browser version needs an extra package: pip install "cybrwire[web]"')
    host = os.environ.get("CYBRWIRE_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("CYBRWIRE_WEB_PORT", "8000"))
    Server(f'"{sys.executable}" -m cybrwire', host=host, port=port, title="CybrWire",
           public_url=os.environ.get("CYBRWIRE_WEB_URL") or None).serve()


if __name__ == "__main__":
    main()
