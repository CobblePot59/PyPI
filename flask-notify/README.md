# Flask-Notify

Real-time notification system for Flask: send popup notifications to the
browser straight from your Python code.
No JavaScript to write and no template changes.

```python
notify("Wrong username or password", "red")
```

- Only the client that made the request sees its notifications (they live in the Flask session).
- Works on normal page loads, after redirects, and on AJAX calls (`fetch`, `XMLHttpRequest`, jQuery, axios, htmx…).
- Any color: CSS names (`red`, `yellow`…), hex (`#ff9900`, `f90`), or aliases (`success`, `error`, `warning`, `info`).
- Text is automatically white or dark depending on the background.
- Popups stack, close automatically with a progress bar, pause on hover, and close on click.
- Message text is never interpreted as HTML.
- Works with a strict Content-Security-Policy (no inline script).

## Installation

```bash
pip install flask-notify
```

## Usage

```python
from flask import Flask, redirect, url_for, render_template
from flask_notify import Notify, notify

app = Flask(__name__)
app.secret_key = "change-me"   # required: notifications are stored in the session
Notify(app)

@app.route("/login", methods=["POST"])
def login():
    if not check_credentials():
        notify("Wrong username or password", "red")
        return render_template("login.html")
    notify("Welcome back!", "green")
    return redirect(url_for("home"))
```

That's it. The extension adds its CSS and script to every HTML page
right before `</body>`, so your templates stay unchanged.

### `notify(message, color="info", duration=5000, title=None)`

| Argument   | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `message`  | Text to display (plain text, HTML is escaped).                              |
| `color`    | `"red"`, `"yellow"`, `"#ff9900"`, `"ff9900"`, `"success"`, `"error"`, `"warning"`, `"info"`… Raises `ValueError` if the value is not a valid color. |
| `duration` | Display time in milliseconds. `0` keeps the popup until it is clicked.     |
| `title`    | Optional bold title above the message.                                      |

```python
notify("Profile saved", "success")
notify("Your session expires in 5 minutes", "#f9a825", duration=0, title="Warning")
```

### Position

```python
Notify(app, position="bottom-right")
# or
app.config["NOTIFY_POSITION"] = "bottom-right"
```

Positions: `top-right` (default), `top-left`, `top-center`, `bottom-right`,
`bottom-left`, `bottom-center`. On screens narrower than 480 px popups use
the full width.

## When is a notification shown?

The server cannot push to the browser on its own: a notification is
delivered with a response to a request made by that client.

| Response                                                   | What happens                                                                 |
|------------------------------------------------------------|------------------------------------------------------------------------------|
| HTML page containing `</body>`                             | Popup shown when the page loads.                                             |
| Redirect (3xx)                                             | Kept, and shown on the page the browser is redirected to.                    |
| AJAX call (`fetch` / `XMLHttpRequest`) from a page of the app | Sent in the `X-Notify-Messages` header and shown immediately.             |
| Anything else (JSON from another client, file download…)   | Kept until the next response that can display it.                            |

AJAX example, with no JavaScript change needed on your side:

```python
@app.post("/api/cart")
def add_to_cart():
    ...
    notify("Added to cart", "success")
    return {"ok": True}
```

The bundled script adds an `X-Notify: 1` header to same-origin AJAX requests
only (cross-origin requests are left untouched).

## Behind a reverse proxy (nginx, Traefik, Caddy…) with HTTPS

Nothing specific is needed: the CSS and JS URLs are relative, so they follow
the scheme and host used by the browser. Recommended settings for any Flask app
behind a proxy:

```python
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config["SESSION_COOKIE_SECURE"] = True   # session cookie only sent over HTTPS
```

If the app is served under a sub-path (e.g. `https://example.com/myapp/`),
the proxy must send `X-Forwarded-Prefix: /myapp` so that `ProxyFix` (with
`x_prefix=1`) builds the correct URLs for the static files.

## License

Copyright (C) 2026 CobblePot59

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. See [LICENSE](LICENSE).
