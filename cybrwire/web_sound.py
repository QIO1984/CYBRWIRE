"""
Sound in the browser version.

A browser tab can't play what the app plays on a local speaker, so the app sends a small message
through textual-serve instead and a script in the page makes the tone with WebAudio. Browsers only
allow sound after you have pressed a key or clicked in the page, so the first alert after opening
the tab can be silent.

This leans on textual-serve internals (its websocket and its handling of messages from the app), so
it is the part most likely to need attention when that package changes. If anything here fails, the
app carries on without sound.
"""

import json

MESSAGE = "cybrwire_sound"

SCRIPT = r"""
(function () {
  var NativeWS = window.WebSocket, ctx = null, hum = null;
  function audio() {
    if (!ctx) { try { ctx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { ctx = null; } }
    return ctx;
  }
  // Browsers keep audio locked until the page has had a key press or a click
  ["keydown", "pointerdown", "click", "touchstart"].forEach(function (name) {
    addEventListener(name, function () { var c = audio(); if (c && c.state === "suspended") c.resume(); }, true);
  });
  function tone(freq, start, length, type, gain, decay) {
    var c = audio(); if (!c) return;
    var osc = c.createOscillator(), amp = c.createGain(), t0 = c.currentTime + start;
    osc.type = type; osc.frequency.setValueAtTime(freq, t0);
    amp.gain.setValueAtTime(0.0001, t0);
    amp.gain.linearRampToValueAtTime(gain, t0 + 0.004);
    if (decay) amp.gain.exponentialRampToValueAtTime(0.0001, t0 + length); else amp.gain.setValueAtTime(gain, t0 + length - 0.01);
    amp.gain.linearRampToValueAtTime(0, t0 + length);
    osc.connect(amp); amp.connect(c.destination); osc.start(t0); osc.stop(t0 + length + 0.02);
  }
  var SOUNDS = {
    pc: function () { tone(800, 0, 0.25, "square", 0.08, false); },
    teletype: function () { tone(1760, 0, 0.7, "sine", 0.18, true); tone(2640, 0, 0.7, "sine", 0.09, true); },
    modem: function () { for (var i = 0; i < 7; i++) tone(i % 2 ? 2400 : 1200, i * 0.06, 0.06, "square", 0.05, false); },
    sonar: function () { tone(1250, 0, 0.95, "sine", 0.22, true); tone(1250, 0.32, 0.6, "sine", 0.08, true); },
    bell: function () { tone(880, 0, 0.18, "sine", 0.15, true); }
  };
  function play(name) { if (SOUNDS[name]) SOUNDS[name](); }
  function humOn(on) {
    var c = audio(); if (!c) return;
    if (hum) { try { hum.a.stop(); hum.b.stop(); } catch (e) {} hum = null; }
    if (!on) return;
    var a = c.createOscillator(), b = c.createOscillator(), amp = c.createGain();
    a.frequency.value = 55; b.frequency.value = 55.6; a.type = b.type = "sine"; amp.gain.value = 0.025;
    a.connect(amp); b.connect(amp); amp.connect(c.destination); a.start(); b.start(); hum = { a: a, b: b };
  }
  function Wrapped(url, protocols) {
    var ws = protocols === undefined ? new NativeWS(url) : new NativeWS(url, protocols);
    ws.addEventListener("message", function (ev) {
      if (typeof ev.data !== "string" || ev.data.indexOf('["__MESSAGE__"') !== 0) return;
      try {
        var msg = JSON.parse(ev.data)[1];
        if (msg.hum !== undefined) humOn(!!msg.hum); else play(msg.name);
      } catch (e) {}
    });
    return ws;
  }
  Wrapped.prototype = NativeWS.prototype;
  ["CONNECTING", "OPEN", "CLOSING", "CLOSED"].forEach(function (k, i) { Wrapped[k] = i; });
  window.WebSocket = Wrapped;
})();
""".replace("__MESSAGE__", MESSAGE)

SCRIPT_PATH = "/cybrwire-sound.js"
TAG = f'<script src="{SCRIPT_PATH}"></script>'


def inject(html: str) -> str:
    """The page with the sound script loaded before textual-serve's own, so it sees the websocket being made"""
    if SCRIPT_PATH in html or "<script" not in html:
        return html
    return html.replace("<script", TAG + "<script", 1)


def make_middleware():
    from aiohttp import web

    @web.middleware
    async def add_sound(request, handler):
        resp = await handler(request)
        if request.path == "/" and request.method == "GET" and isinstance(resp, web.Response) \
                and (resp.content_type or "").startswith("text/html") and resp.text:
            resp.text = inject(resp.text)
        return resp
    return add_sound


async def script_response(request):
    from aiohttp import web
    return web.Response(text=SCRIPT, content_type="application/javascript", headers={"Cache-Control": "no-cache"})


def make_service_class(base):
    """textual-serve's app service, also passing our sound messages on to the page"""

    class SoundAppService(base):
        async def on_meta(self, data: bytes) -> None:
            try:
                meta = json.loads(data)
            except ValueError:
                meta = {}
            if meta.get("type") == MESSAGE:
                payload = {k: v for k, v in meta.items() if k != "type"}
                await self.remote_write_str(json.dumps([MESSAGE, payload]))
                return
            await super().on_meta(data)

    return SoundAppService


def install() -> None:
    """Make textual-serve use the sound-aware service. Quietly does nothing if its layout has changed."""
    try:
        from textual_serve import server
        if not getattr(server.AppService, "_cybrwire_sound", False):
            cls = make_service_class(server.AppService)
            cls._cybrwire_sound = True
            server.AppService = cls
    except Exception:  # A different textual-serve: no sound in the browser, nothing else affected
        pass
