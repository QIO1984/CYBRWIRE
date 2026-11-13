"""Open a link: in a terminal that is the local browser; in the browser version, a new tab in the page"""

import os
import webbrowser


def in_browser_mode() -> bool:
    return "web_driver" in os.environ.get("TEXTUAL_DRIVER", "")


def open_link(app, url: str) -> None:
    if in_browser_mode():
        # The page opens it. A container has no browser of its own for webbrowser to start.
        app.open_url(url, new_tab=True)
    else:
        webbrowser.open(url)
