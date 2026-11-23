/*!
 * Flask-Notify — displays the popups sent by notify() on the Flask server.
 * Copyright (C) 2026 CobblePot59 — GPL-3.0-or-later
 * Loaded automatically by the extension; you never need to call it yourself.
 *
 * - On page load, shows the notifications embedded in #flask-notify-data.
 * - On same-origin fetch / XMLHttpRequest calls, sends an "X-Notify: 1"
 *   header and shows the notifications returned in "X-Notify-Messages".
 */
(function (window, document) {
  "use strict";

  if (window.flaskNotify) return; // already loaded

  var ALIASES = {
    success: "#2e7d32",
    error: "#c62828",
    danger: "#c62828",
    warning: "#f9a825",
    info: "#1565c0"
  };

  var script = document.currentScript;
  var config = {
    position: (script && script.getAttribute("data-position")) || "top-right",
    duration: 5000,
    max: 5
  };

  var container = null;

  function getContainer() {
    if (container && document.body.contains(container)) return container;
    container = document.createElement("div");
    container.className = "flask-notify-container flask-notify-" + config.position;
    container.setAttribute("aria-live", "polite");
    document.body.appendChild(container);
    return container;
  }

  function resolveColor(color) {
    if (!color) return ALIASES.info;
    color = String(color).trim();
    if (ALIASES[color.toLowerCase()]) return ALIASES[color.toLowerCase()];
    if (/^[0-9a-f]{3,8}$/i.test(color)) color = "#" + color; // "ff0000" -> "#ff0000"
    return window.CSS && CSS.supports("color", color) ? color : ALIASES.info;
  }

  // White or dark text depending on the background brightness.
  function textColor(el) {
    var rgb = getComputedStyle(el).backgroundColor.match(/[\d.]+/g);
    if (!rgb) return "#fff";
    var luminance = (0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2]) / 255;
    return luminance > 0.6 ? "#1a1a1a" : "#fff";
  }

  function close(toast) {
    if (toast._closing) return;
    toast._closing = true;
    clearTimeout(toast._timer);
    toast.classList.add("flask-notify-out");
    toast.addEventListener("animationend", function () { toast.remove(); });
  }

  function show(message, color, options) {
    options = options || {};
    var duration = options.duration != null ? options.duration : config.duration;

    var box = getContainer();
    while (box.children.length >= config.max) box.firstElementChild.remove(); // drop the oldest

    var toast = document.createElement("div");
    toast.className = "flask-notify-toast";
    toast.setAttribute("role", "alert");
    toast.style.backgroundColor = resolveColor(color);

    var closeButton = document.createElement("button");
    closeButton.className = "flask-notify-close";
    closeButton.type = "button";
    closeButton.setAttribute("aria-label", "Close");
    closeButton.innerHTML = "&times;";
    toast.appendChild(closeButton);

    if (options.title) {
      var title = document.createElement("strong");
      title.className = "flask-notify-title";
      title.textContent = options.title;
      toast.appendChild(title);
    }
    var text = document.createElement("div");
    text.className = "flask-notify-message";
    text.textContent = message; // plain text: no HTML injection
    toast.appendChild(text);

    box.appendChild(toast);
    toast.style.color = textColor(toast);
    toast.addEventListener("click", function () { close(toast); });

    if (duration > 0) {
      var bar = document.createElement("div");
      bar.className = "flask-notify-progress";
      bar.style.animationDuration = duration + "ms";
      toast.appendChild(bar);

      var remaining = duration, startedAt;
      var start = function () {
        startedAt = Date.now();
        toast._timer = setTimeout(function () { close(toast); }, remaining);
        bar.style.animationPlayState = "running";
      };
      // Pause while hovered.
      toast.addEventListener("mouseenter", function () {
        clearTimeout(toast._timer);
        remaining -= Date.now() - startedAt;
        bar.style.animationPlayState = "paused";
      });
      toast.addEventListener("mouseleave", start);
      start();
    }
    return toast;
  }

  function showAll(list) {
    if (!Array.isArray(list)) return;
    list.forEach(function (n) { show(n.message, n.color, n); });
  }

  function showFromHeader(value) {
    if (!value) return;
    try { showAll(JSON.parse(value)); } catch (e) { /* malformed header: ignore */ }
  }

  function isSameOrigin(url) {
    try { return new URL(url, window.location.href).origin === window.location.origin; }
    catch (e) { return false; }
  }

  // --- fetch() ---------------------------------------------------------------
  // Only same-origin requests get the header: adding a custom header to a
  // cross-origin request would trigger a CORS preflight.
  if (window.fetch) {
    var originalFetch = window.fetch;
    window.fetch = function (input, init) {
      var url = input instanceof Request ? input.url : String(input);
      if (isSameOrigin(url)) {
        init = Object.assign({}, init);
        var headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
        headers.set("X-Notify", "1");
        init.headers = headers;
      }
      return originalFetch.call(this, input, init).then(function (response) {
        showFromHeader(response.headers.get("X-Notify-Messages"));
        return response;
      });
    };
  }

  // --- XMLHttpRequest (jQuery.ajax, axios, htmx...) ---------------------------
  var originalOpen = XMLHttpRequest.prototype.open;
  var originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this._flaskNotifySameOrigin = isSameOrigin(url);
    return originalOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    if (this._flaskNotifySameOrigin) {
      this.setRequestHeader("X-Notify", "1");
      this.addEventListener("load", function () {
        showFromHeader(this.getResponseHeader("X-Notify-Messages"));
      });
    }
    return originalSend.apply(this, arguments);
  };

  // --- Notifications embedded in the page -------------------------------------
  var data = document.getElementById("flask-notify-data");
  if (data) {
    try { showAll(JSON.parse(data.textContent)); } catch (e) { /* ignore */ }
  }

  window.flaskNotify = show;
})(window, document);
