"""
Flask-Notify: real-time popup notifications sent from your Flask views.

Copyright (C) 2026 CobblePot59
Licensed under the GNU General Public License v3 or later (see LICENSE).

    from flask_notify import Notify, notify

    Notify(app)
    notify("Wrong username or password", "red")

Notifications are stored in the Flask session, so only the client that made
the request sees them. They are delivered with the next response that can
display them:

* a full HTML page: the popup is injected right before ``</body>``;
* an AJAX request (fetch / XMLHttpRequest) made from a page served by the
  app: the popup is sent in the ``X-Notify-Messages`` response header and
  displayed by the bundled script.

Redirects, JSON responses from other clients, file downloads, etc. keep the
notifications for the next response that can show them.
"""

import json
import re

from flask import Blueprint, request, session, url_for

__all__ = ["Notify", "notify"]
__version__ = "0.1.0"

SESSION_KEY = "_flask_notify"
REQUEST_HEADER = "X-Notify"  # sent by notify.js on same-origin AJAX requests
RESPONSE_HEADER = "X-Notify-Messages"  # JSON list of notifications

POSITIONS = {"top-right", "top-left", "top-center", "bottom-right", "bottom-left", "bottom-center"}

ALIASES = {
    "success": "#2e7d32",
    "error": "#c62828",
    "danger": "#c62828",
    "warning": "#f9a825",
    "info": "#1565c0",
}

_HEX = re.compile(r"^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
_NAME = re.compile(r"^[a-zA-Z]{3,30}$")  # red, yellow, rebeccapurple...


def normalize_color(color):
    """Return a safe CSS color, or raise ValueError.

    Accepts an alias (success, error, warning, info, danger), a CSS color
    name (red, yellow...) or a hex value with or without "#"
    (#f00, ff0000, #ff000080).
    """
    if not color:
        return ALIASES["info"]
    color = str(color).strip()
    if color.lower() in ALIASES:
        return ALIASES[color.lower()]
    if _HEX.match(color):
        return "#" + color.lstrip("#").lower()
    if _NAME.match(color):
        return color.lower()
    raise ValueError(f"Invalid notify color: {color!r}")


def notify(message, color="info", duration=5000, title=None):
    """Send a popup notification to the client making the current request.

    :param message:  text to display (rendered as plain text, never HTML)
    :param color:    "red", "yellow", "#ff9900", "success"...
    :param duration: display time in milliseconds (0 = stays until clicked)
    :param title:    optional bold title
    """
    queue = session.get(SESSION_KEY, [])
    queue.append(
        {
            "message": str(message),
            "color": normalize_color(color),
            "duration": max(0, int(duration)),
            "title": str(title) if title else None,
        }
    )
    session[SESSION_KEY] = queue


class Notify:
    """Flask extension. Use ``Notify(app)`` or ``Notify().init_app(app)``.

    :param position: where popups appear: top-right (default), top-left,
                     top-center, bottom-right, bottom-left, bottom-center.
                     Can also be set with the ``NOTIFY_POSITION`` config key.
    """

    def __init__(self, app=None, position=None):
        self.position = position
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        position = self.position or app.config.get("NOTIFY_POSITION", "top-right")
        if position not in POSITIONS:
            raise ValueError(f"Invalid notify position: {position!r}")
        self.position = position

        app.register_blueprint(
            Blueprint(
                "flask_notify",
                __name__,
                static_folder="static",
                static_url_path="/static/flask_notify",
            )
        )
        app.extensions["notify"] = self
        app.after_request(self._after_request)

    def _assets(self, messages):
        # The pending messages are a JSON data block, not executable script,
        # so this works with a strict Content-Security-Policy.
        data = json.dumps(messages).replace("<", "\\u003c").replace(">", "\\u003e")
        css = url_for("flask_notify.static", filename="notify.css")
        js = url_for("flask_notify.static", filename="notify.js")
        return (
            f'<link rel="stylesheet" href="{css}">\n'
            f'<script type="application/json" id="flask-notify-data">{data}</script>\n'
            f'<script src="{js}" data-position="{self.position}"></script>\n'
        )

    def _after_request(self, response):
        # Redirects are followed by the browser (and by fetch), so the
        # notifications are kept for the response at the end of the redirect.
        if (
            request.blueprint == "flask_notify"
            or response.direct_passthrough
            or 300 <= response.status_code < 400
        ):
            return response

        # 1. AJAX request from a page that runs notify.js: use a header.
        if request.headers.get(REQUEST_HEADER):
            if SESSION_KEY in session:
                messages = session.pop(SESSION_KEY)
                response.headers[RESPONSE_HEADER] = json.dumps(messages)  # ASCII-only
            return response

        # 2. Full HTML page: always load the script (so later AJAX calls can
        #    show popups) and include any pending notifications.
        if response.mimetype != "text/html":
            return response  # JSON, files...: keep them for later
        body = response.get_data(as_text=True)
        pos = body.lower().rfind("</body>")
        if pos == -1:
            return response
        messages = session.pop(SESSION_KEY) if SESSION_KEY in session else []
        response.set_data(body[:pos] + self._assets(messages) + body[pos:])
        return response
