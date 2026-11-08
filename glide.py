"""
Glide - control your laptop's mouse & keyboard from your phone's browser.

See README.md for setup. Quick version:
  pip install pynput cryptography
  python glide.py --install     start now and at every login
  python glide.py --link        show your link
"""
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from pynput.mouse import Controller as MouseController, Button
from pynput.keyboard import Controller as KeyboardController, Key

PORT = 8765
HOME = os.path.join(os.path.expanduser("~"), ".glide")
CONFIG = os.path.join(HOME, "config.json")
CERT = os.path.join(HOME, "cert.pem")
KEY = os.path.join(HOME, "key.pem")
SCRIPT = os.path.abspath(__file__)
APP_ID = "com.glide.server"

MAX_DEVICES = 3              # phones that may pair with one link
MAX_BODY = 4096              # bytes per request
FAIL_LIMIT = 10              # wrong tokens from one IP ...
FAIL_WINDOW = 600            # ... within this many seconds -> blocked for that long

mouse = MouseController()
keyboard = KeyboardController()


# ---------------------------------------------------------------- config & secrets
def write_private(path, data):
    """Write a file only the current user can read (atomic replace)."""
    os.makedirs(HOME, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


_lock = threading.RLock()
_cache = {"mtime": None, "cfg": None}


def _save(cfg):
    write_private(CONFIG, json.dumps(cfg).encode())
    _cache.update(mtime=os.stat(CONFIG).st_mtime_ns, cfg=cfg)


def config(reset=False):
    """Token + paired devices. Re-read when the file changes, so --reset takes
    effect on an already-running server."""
    with _lock:
        try:
            mtime = os.stat(CONFIG).st_mtime_ns
        except OSError:
            mtime = None
        if not reset and mtime is not None and mtime == _cache["mtime"]:
            return _cache["cfg"]
        cfg = None
        if not reset:
            try:
                with open(CONFIG) as f:
                    cfg = json.load(f)
                if not (isinstance(cfg.get("token"), str) and len(cfg["token"]) >= 32
                        and isinstance(cfg.get("devices"), list)):
                    cfg = None
            except (OSError, ValueError, AttributeError):
                cfg = None
        if cfg is None:
            cfg = {"token": secrets.token_urlsafe(32), "devices": []}
            _save(cfg)
        else:
            _cache.update(mtime=mtime, cfg=cfg)
        return cfg


def pair_device():
    with _lock:
        cfg = config()
        if len(cfg["devices"]) >= MAX_DEVICES:
            return None
        dev = secrets.token_urlsafe(32)
        _save({**cfg, "devices": cfg["devices"] + [dev]})
        return dev


def same(a, b):
    return hmac.compare_digest(str(a).encode(), str(b).encode())


# ---------------------------------------------------------------- brute-force guard
_fails = {}
_fails_lock = threading.Lock()


def blocked(ip):
    with _fails_lock:
        now = time.monotonic()
        recent = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW]
        if recent:
            _fails[ip] = recent
        else:
            _fails.pop(ip, None)
        return len(recent) >= FAIL_LIMIT


def record_fail(ip):
    with _fails_lock:
        _fails.setdefault(ip, []).append(time.monotonic())


# ---------------------------------------------------------------- TLS certificate
def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no data is sent; just picks the WiFi interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def hostname():
    return socket.gethostname().split(".")[0]


def ensure_cert():
    """Self-signed certificate, made once and kept in ~/.glide/."""
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    host, ip = hostname(), local_ip()
    try:
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        try:  # fallback: openssl on PATH
            os.makedirs(HOME, exist_ok=True)
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-nodes", "-keyout", KEY, "-out", CERT, "-days", "825", "-subj", "/CN=Glide",
                 "-addext", f"subjectAltName=DNS:{host}.local,DNS:localhost,IP:{ip}"],
                check=True, capture_output=True)
            os.chmod(KEY, 0o600)
            return
        except (OSError, subprocess.CalledProcessError):
            sys.exit("\n  Glide needs a TLS certificate. Run:  pip install cryptography\n")

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Glide")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))  # iOS max for trusted certs
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(f"{host}.local"), x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    write_private(KEY, key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    write_private(CERT, cert.public_bytes(serialization.Encoding.PEM))


def fingerprint():
    with open(CERT) as f:
        der = ssl.PEM_cert_to_DER_cert(f.read())
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


# ---------------------------------------------------------------- input actions
KEY_NAMES = [
    "enter", "backspace", "tab", "esc", "space", "delete", "home", "end", "page_up", "page_down",
    "up", "down", "left", "right", "ctrl", "alt", "shift", "cmd",
    "media_play_pause", "media_next", "media_previous",
    "media_volume_up", "media_volume_down", "media_volume_mute",
]
KEYS = {n: getattr(Key, n) for n in KEY_NAMES if hasattr(Key, n)}


def to_key(name):
    """Named key (e.g. 'ctrl') or a single character (e.g. 'c')."""
    if name in KEYS:
        return KEYS[name]
    if isinstance(name, str) and len(name) == 1:
        return name
    return None


def clamp(v, lim):
    return max(-lim, min(lim, int(v)))


def act(a, d):
    btn = Button.right if d.get("b") == "right" else Button.left
    if a == "move":
        mouse.move(clamp(d["dx"], 5000), clamp(d["dy"], 5000))
    elif a == "click":
        mouse.click(btn)
    elif a == "press":
        mouse.press(btn)
    elif a == "release":
        mouse.release(btn)
    elif a == "scroll":
        mouse.scroll(0, clamp(d["dy"], 200))
    elif a == "type":
        if isinstance(d.get("text"), str):
            keyboard.type(d["text"])
    elif a == "key":
        k = to_key(d.get("k"))
        if k is not None:
            keyboard.press(k)
            keyboard.release(k)
    elif a == "hotkey":
        names = d.get("keys")
        if isinstance(names, list) and len(names) <= 5:
            ks = [k for k in (to_key(n) for n in names) if k is not None]
            for k in ks:
                keyboard.press(k)
            for k in reversed(ks):
                keyboard.release(k)


# ---------------------------------------------------------------- web page
PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover,interactive-widget=resizes-content">
<title>Glide</title>
<meta name="theme-color" content="#0b0d10">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Glide">
<meta name="referrer" content="no-referrer">
<link rel="manifest" href="/manifest.json?t=__TOKEN__">
<link rel="icon" href="/icon.svg?t=__TOKEN__">
<link rel="apple-touch-icon" href="/icon.svg?t=__TOKEN__">
<style>
:root{
  --bg:#0b0d10; --surface:#14171c; --surface2:#1b1f26; --line:#262b34;
  --text:#e9edf3; --muted:#7d8694; --accent:#5b8cff; --accent2:#8a6bff;
  --good:#3ddc97; --bad:#ff5d6c; --r:16px;
}
*{box-sizing:border-box;margin:0;-webkit-user-select:none;user-select:none;-webkit-tap-highlight-color:transparent}
html,body{height:100%;background:var(--bg);color:var(--text);
  font:15px/1.3 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;overflow:hidden}
body{display:flex;flex-direction:column;height:100dvh;padding:env(safe-area-inset-top) 0 0}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* header */
header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px 8px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.brand b{display:block;font-size:17px;letter-spacing:.2px}
.brand small{display:block;color:var(--muted);font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#dot{flex:none;width:10px;height:10px;border-radius:50%;background:var(--bad);box-shadow:0 0 0 4px #ff5d6c22;transition:.3s}
#dot.on{background:var(--good);box-shadow:0 0 0 4px #3ddc9722}
.icon{flex:none;width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:var(--surface);border:1px solid var(--line);color:var(--muted)}
.icon:active{transform:scale(.94)}
.icon.on{border-color:var(--accent);color:var(--accent)}

/* views */
main{flex:1;position:relative;min-height:0}
.view{position:absolute;inset:0;padding:4px 14px 10px;display:flex;flex-direction:column;gap:10px;
  opacity:0;pointer-events:none;transform:translateY(8px);transition:opacity .2s,transform .2s}
.view.active{opacity:1;pointer-events:auto;transform:none}
#ctl>*:not(.padwrap){flex-shrink:0}
#media{overflow-y:auto}

/* touchpad */
.padwrap{flex:1;display:flex;gap:10px;min-height:120px}
#pad{flex:1;position:relative;overflow:hidden;touch-action:none;border-radius:22px;
  background:
    radial-gradient(circle at 50% 0%,#5b8cff14,transparent 60%),
    radial-gradient(#ffffff0d 1.2px,transparent 1.2px) 0 0/22px 22px,
    var(--surface);
  border:1px solid var(--line);transition:border-color .2s,box-shadow .2s}
#pad.drag{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent),0 0 30px #5b8cff33}
#hint{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:10px;color:var(--muted);font-size:13px;transition:opacity .6s;pointer-events:none}
#hint.gone{opacity:0}
#hint div{display:flex;gap:8px;align-items:center}
#hint kbd{font:600 11px system-ui;background:var(--surface2);border:1px solid var(--line);
  padding:3px 8px;border-radius:7px;color:var(--text)}
.rip{position:absolute;width:70px;height:70px;margin:-35px 0 0 -35px;border-radius:50%;pointer-events:none;
  background:radial-gradient(#5b8cff55,#5b8cff00 70%);animation:rip .5s ease-out forwards}
@keyframes rip{from{transform:scale(.3);opacity:1}to{transform:scale(1.6);opacity:0}}
#strip{width:38px;border-radius:19px;background:var(--surface);border:1px solid var(--line);touch-action:none;
  display:flex;flex-direction:column;align-items:center;justify-content:space-between;padding:14px 0;color:var(--muted)}
#strip i{flex:1;width:2px;margin:10px 0;border-radius:2px;
  background:repeating-linear-gradient(var(--line) 0 6px,transparent 6px 12px)}
#strip.on{border-color:var(--accent);color:var(--accent)}
.clicks{display:grid;grid-template-columns:1fr 1fr;gap:10px;height:54px}
.clicks button{border-radius:var(--r);background:var(--surface);border:1px solid var(--line);
  color:var(--muted);font-size:13px;letter-spacing:.5px;text-transform:uppercase;transition:.1s}
.clicks button:active,.clicks button.on{background:var(--surface2);color:var(--text);transform:scale(.98)}

/* typing bar + extra keys */
.typebar{display:flex;gap:10px}
.field{position:relative;flex:1}
#kb{width:100%;height:48px;padding:0 14px 0 44px;font-size:16px;border-radius:var(--r);border:1px solid var(--line);
  background:var(--surface);color:var(--text);outline:none;-webkit-user-select:text;user-select:text}
#kb:focus{border-color:var(--accent)}
.field svg{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--muted)}
#extra{display:none;flex-direction:column;gap:8px;max-height:38dvh;overflow-y:auto}
#extra.open{display:flex}
.grid{display:grid;gap:8px}
.g4{grid-template-columns:repeat(4,1fr)}
.g3{grid-template-columns:repeat(3,1fr)}
.k{height:44px;border-radius:12px;background:var(--surface);border:1px solid var(--line);font-size:14px;
  display:flex;align-items:center;justify-content:center;gap:6px;transition:.08s}
.k:active{background:var(--surface2);transform:scale(.96)}
.k small{color:var(--muted);font-size:11px}
.mod.on{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent;color:#fff}
.nav{display:grid;grid-template-columns:repeat(4,1fr);grid-template-rows:44px 44px;gap:8px}
.nav .up{grid-column:2;grid-row:1}
.nav .lf{grid-column:1;grid-row:2}.nav .dn{grid-column:2;grid-row:2}.nav .rt{grid-column:3;grid-row:2}
.nav .en{grid-column:4;grid-row:1/3;height:auto}

/* media */
.player{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:34px;min-height:300px}
.transport{display:flex;align-items:center;gap:26px}
.round{width:66px;height:66px;border-radius:50%;background:var(--surface);border:1px solid var(--line);display:grid;place-items:center}
.round:active{transform:scale(.93)}
.play{width:96px;height:96px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:0;
  box-shadow:0 12px 40px #5b8cff44;color:#fff}
.play svg{width:34px;height:34px;fill:#fff;stroke:none}
.vol{display:flex;gap:12px;width:100%;max-width:340px}
.vol .k{flex:1;height:58px}

/* tab bar */
nav.tabs{display:grid;grid-template-columns:repeat(2,1fr);margin:0 14px calc(10px + env(safe-area-inset-bottom));
  background:var(--surface);border:1px solid var(--line);border-radius:22px;padding:6px}
.tab{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px 0;border-radius:16px;
  color:var(--muted);font-size:13px;transition:.2s}
.tab.active{background:var(--surface2);color:var(--text)}
.tab.active svg{color:var(--accent)}

/* settings sheet */
#sheet{position:fixed;inset:0;background:#0009;opacity:0;pointer-events:none;transition:.25s;display:flex;align-items:flex-end;z-index:9}
#sheet.open{opacity:1;pointer-events:auto}
.panel{width:100%;background:var(--surface);border-top:1px solid var(--line);border-radius:26px 26px 0 0;
  padding:10px 20px calc(24px + env(safe-area-inset-bottom));transform:translateY(100%);transition:transform .3s cubic-bezier(.2,.9,.3,1)}
#sheet.open .panel{transform:none}
.grab{width:40px;height:5px;border-radius:3px;background:var(--line);margin:0 auto 16px}
.panel h3{font-size:17px;margin-bottom:12px}
.row{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid var(--line);gap:16px}
.row:last-child{border:0}
.row span small{display:block;color:var(--muted);font-size:12px;margin-top:2px}
input[type=range]{-webkit-appearance:none;appearance:none;width:150px;height:4px;border-radius:2px;background:var(--line)}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;border-radius:50%;background:var(--accent);border:3px solid var(--surface)}
.sw{width:50px;height:30px;border-radius:15px;background:var(--line);position:relative;transition:.2s;flex:none}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:24px;height:24px;border-radius:50%;background:#fff;transition:.2s}
.sw.on{background:var(--accent)} .sw.on::after{left:23px}
</style></head><body>

<header>
  <div class="brand"><span id="dot"></span><div><b>Glide</b><small id="host">Connecting…</small></div></div>
  <button class="icon" id="gear" aria-label="Settings"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg></button>
</header>

<main>
  <!-- CONTROL: touchpad + keyboard together -->
  <section class="view active" id="ctl">
    <div class="padwrap">
      <div id="pad">
        <div id="hint">
          <div><kbd>Tap</kbd> click</div>
          <div><kbd>2-finger tap</kbd> right-click</div>
          <div><kbd>2-finger drag</kbd> scroll</div>
          <div><kbd>Double-tap &amp; drag</kbd> select / move</div>
        </div>
      </div>
      <div id="strip"><svg viewBox="0 0 24 24"><path d="m18 15-6-6-6 6"/></svg><i></i><svg viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></div>
    </div>
    <div class="clicks"><button id="lc">Left</button><button id="rc">Right</button></div>

    <div class="typebar">
      <div class="field">
        <svg viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/></svg>
        <input id="kb" placeholder="Type on your laptop" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" enterkeyhint="send">
      </div>
      <button class="icon" id="more" aria-label="More keys"><svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h10"/></svg></button>
    </div>

    <div id="extra">
      <div class="grid g4">
        <button class="k mod" data-m="ctrl">Ctrl</button><button class="k mod" data-m="alt" id="altk">Alt</button>
        <button class="k mod" data-m="shift">Shift</button><button class="k mod" data-m="cmd" id="wink">Win</button>
      </div>
      <div class="grid g4">
        <button class="k" data-k="esc">Esc</button><button class="k" data-k="tab">Tab</button>
        <button class="k" data-k="delete">Del</button><button class="k" data-k="backspace">⌫</button>
        <button class="k" data-k="home">Home</button><button class="k" data-k="end">End</button>
        <button class="k" data-k="page_up">PgUp</button><button class="k" data-k="page_down">PgDn</button>
      </div>
      <div class="nav">
        <button class="k up" data-k="up">↑</button>
        <button class="k lf" data-k="left">←</button><button class="k dn" data-k="down">↓</button><button class="k rt" data-k="right">→</button>
        <button class="k en" data-k="enter">⏎</button>
      </div>
      <div class="grid g3">
        <button class="k" data-c="MOD,c">Copy</button><button class="k" data-c="MOD,v">Paste</button><button class="k" data-c="MOD,x">Cut</button>
        <button class="k" data-c="MOD,z">Undo</button><button class="k" data-c="MOD,a">Select all</button><button class="k" data-c="SWITCH">Switch app</button>
        <button class="k" data-c="MOD,w">Close tab</button><button class="k" data-c="MOD,t">New tab</button><button class="k" data-c="MOD,f">Find</button>
      </div>
    </div>
  </section>

  <!-- MEDIA -->
  <section class="view" id="media">
    <div class="player">
      <div class="transport">
        <button class="round" data-k="media_previous"><svg viewBox="0 0 24 24"><path d="M19 20 9 12l10-8v16zM5 19V5"/></svg></button>
        <button class="round play" data-k="media_play_pause"><svg viewBox="0 0 24 24"><path d="M7 4v16l13-8z"/></svg></button>
        <button class="round" data-k="media_next"><svg viewBox="0 0 24 24"><path d="m5 4 10 8-10 8V4zM19 5v14"/></svg></button>
      </div>
      <div class="vol">
        <button class="k" data-k="media_volume_down"><svg viewBox="0 0 24 24"><path d="M11 5 6 9H2v6h4l5 4V5zM16 12h5"/></svg></button>
        <button class="k" data-k="media_volume_mute"><svg viewBox="0 0 24 24"><path d="M11 5 6 9H2v6h4l5 4V5zM23 9l-6 6M17 9l6 6"/></svg></button>
        <button class="k" data-k="media_volume_up"><svg viewBox="0 0 24 24"><path d="M11 5 6 9H2v6h4l5 4V5zM16 12h6M19 9v6"/></svg></button>
      </div>
      <div class="vol">
        <button class="k" data-k="space">Space <small>pause video</small></button>
        <button class="k" data-k="f">F <small>fullscreen</small></button>
      </div>
    </div>
  </section>
</main>

<nav class="tabs">
  <button class="tab active" data-v="ctl"><svg viewBox="0 0 24 24"><rect x="5" y="2" width="14" height="20" rx="7"/><path d="M12 6v4"/></svg>Control</button>
  <button class="tab" data-v="media"><svg viewBox="0 0 24 24"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>Media</button>
</nav>

<div id="sheet"><div class="panel">
  <div class="grab"></div>
  <h3>Settings</h3>
  <div class="row"><span>Pointer speed</span><input type="range" id="s-speed" min="0.5" max="4" step="0.1"></div>
  <div class="row"><span>Scroll speed</span><input type="range" id="s-scroll" min="0.3" max="3" step="0.1"></div>
  <div class="row"><span>Natural scrolling<small>Content follows your fingers</small></span><button class="sw" id="s-natural"></button></div>
  <div class="row"><span>Vibration<small>Feedback on taps (Android)</small></span><button class="sw" id="s-haptics"></button></div>
</div></div>

<script>
const T = new URLSearchParams(location.search).get('t') || '';
const $ = s => document.querySelector(s), $$ = s => document.querySelectorAll(s);
const store = {
  get: k => { try { return localStorage.getItem(k); } catch(e) { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch(e) {} },
  del: k => { try { localStorage.removeItem(k); } catch(e) {} },
};

/* ---------- auth: secret link token + per-phone device key ---------- */
let DEV = store.get('glide-dev');
const post = (o, signal) => fetch('/api', {method:'POST', body:JSON.stringify(o), signal,
  headers:{'X-Glide-Token':T, 'X-Glide-Device':DEV || ''}});
const send = o => DEV ? post(o).catch(()=>{}) : Promise.resolve();
let q = Promise.resolve();
const sendQ = o => (q = q.then(() => send(o)));   // keeps clicks/keys in order

let pairing = null;
function pair() {
  if (!pairing) pairing = post({a:'pair'}).then(async r => {
      if (r.ok) { DEV = (await r.json()).device; store.set('glide-dev', DEV); return 'ok'; }
      return r.status === 409 ? 'full' : 'denied';
    }).catch(() => 'offline').finally(() => { pairing = null; });
  return pairing;
}

/* ---------- settings (saved on this phone) ---------- */
const S = Object.assign({speed:1.8, scroll:1, natural:true, haptics:true},
  (() => { try { return JSON.parse(store.get('glide') || '{}'); } catch(e) { return {}; } })());
const save = () => store.set('glide', JSON.stringify(S));
const buzz = (ms=8) => { if (S.haptics && navigator.vibrate) navigator.vibrate(ms); };
['speed','scroll'].forEach(k => { const el = $('#s-'+k); el.value = S[k]; el.oninput = () => { S[k] = +el.value; save(); }; });
['natural','haptics'].forEach(k => { const el = $('#s-'+k); el.classList.toggle('on', S[k]);
  el.onclick = () => { S[k] = !S[k]; el.classList.toggle('on', S[k]); save(); buzz(); }; });
$('#gear').onclick = () => $('#sheet').classList.add('open');
$('#sheet').onclick = e => { if (e.target.id === 'sheet') $('#sheet').classList.remove('open'); };

/* ---------- connection status ---------- */
let MOD = 'ctrl', MAC = false;
const MSG = {
  full: 'Too many phones paired — run glide.py --reset',
  denied: 'Link not valid — run glide.py --link',
  retry: 'Pairing…',
};
async function ping() {
  const c = new AbortController(), to = setTimeout(() => c.abort(), 2500);
  try {
    if (!DEV) { const p = await pair(); if (p !== 'ok') throw p; }
    const r = await post({a:'ping'}, c.signal);
    if (r.status === 401) { DEV = null; store.del('glide-dev'); throw 'retry'; }
    if (r.status === 403) throw 'denied';
    if (!r.ok) throw 'offline';
    const j = await r.json();
    MAC = j.os === 'Darwin'; MOD = MAC ? 'cmd' : 'ctrl';
    $('#wink').textContent = MAC ? '⌘ Cmd' : 'Win'; $('#altk').textContent = MAC ? '⌥ Opt' : 'Alt';
    $('#dot').classList.add('on'); $('#host').textContent = 'Connected · ' + j.host;
  } catch(e) {
    $('#dot').classList.remove('on');
    $('#host').textContent = MSG[e] || 'Not connected — is the laptop on?';
  }
  clearTimeout(to);
}
ping(); setInterval(ping, 3000);

/* ---------- tabs ---------- */
$$('.tab').forEach(b => b.onclick = () => {
  $$('.tab').forEach(x => x.classList.toggle('active', x === b));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === b.dataset.v));
  if (b.dataset.v !== 'ctl') $('#kb').blur();
  buzz(5);
});

/* keep the phone keyboard open while tapping buttons on the control page */
$$('#ctl button').forEach(b => b.addEventListener('mousedown', e => e.preventDefault()));

/* ---------- pointer movement (batched, one request in flight) ---------- */
let ax=0, ay=0, sc=0, busy=false;
async function flush() {
  if (busy) return;
  const dx=Math.round(ax), dy=Math.round(ay), s=Math.round(sc);
  if (!dx && !dy && !s) return;
  ax-=dx; ay-=dy; sc-=s; busy=true;
  if (dx||dy) await send({a:'move', dx, dy});
  if (s) await send({a:'scroll', dy:s});
  busy=false; flush();
}

/* ---------- touchpad gestures ---------- */
const pad = $('#pad');
const avg = ts => { let x=0,y=0; for (const t of ts){x+=t.clientX;y+=t.clientY} return {x:x/ts.length, y:y/ts.length}; };
let last=null, start=0, moved=0, maxF=0, lastTap=0, dragArm=false, dragging=false;

function ripple(t) {
  const r = pad.getBoundingClientRect(), s = document.createElement('i');
  s.className = 'rip'; s.style.left = (t.clientX-r.left)+'px'; s.style.top = (t.clientY-r.top)+'px';
  pad.appendChild(s); setTimeout(() => s.remove(), 500);
}
pad.addEventListener('touchstart', e => {
  e.preventDefault(); $('#hint').classList.add('gone');
  for (const t of e.changedTouches) ripple(t);
  if (maxF === 0) { start = Date.now(); moved = 0; dragArm = e.touches.length === 1 && start - lastTap < 300; }
  maxF = Math.max(maxF, e.touches.length); if (maxF > 1) dragArm = false;
  last = avg(e.touches);
}, {passive:false});

pad.addEventListener('touchmove', e => {
  e.preventDefault();
  const p = avg(e.touches), dx = p.x-last.x, dy = p.y-last.y; last = p;
  moved += Math.abs(dx) + Math.abs(dy);
  if (e.touches.length === 1) {
    if (dragArm && !dragging && moved > 6) { dragging = true; sendQ({a:'press'}); pad.classList.add('drag'); buzz(15); }
    const accel = 1 + Math.min(Math.hypot(dx,dy)/12, 2);
    ax += dx*S.speed*accel; ay += dy*S.speed*accel;
  } else {
    sc += (S.natural ? dy : -dy) / 10 * S.scroll;
  }
  flush();
}, {passive:false});

function endTouch(e) {
  e.preventDefault();
  if (e.touches.length) { last = avg(e.touches); return; }
  const quick = Date.now()-start < 250 && moved < 12;
  if (dragging) { dragging = false; pad.classList.remove('drag'); setTimeout(() => sendQ({a:'release'}), 60); lastTap = 0; }
  else if (quick) { sendQ({a:'click', b: maxF >= 2 ? 'right' : 'left'}); buzz(); lastTap = maxF === 1 ? Date.now() : 0; }
  maxF = 0; dragArm = false;
}
pad.addEventListener('touchend', endTouch, {passive:false});
pad.addEventListener('touchcancel', endTouch, {passive:false});

/* scroll strip */
const strip = $('#strip'); let sy = 0;
strip.addEventListener('touchstart', e => { e.preventDefault(); sy = e.touches[0].clientY; strip.classList.add('on'); }, {passive:false});
strip.addEventListener('touchmove', e => { e.preventDefault(); const y = e.touches[0].clientY;
  sc += (S.natural ? y-sy : sy-y) / 7 * S.scroll; sy = y; flush(); }, {passive:false});
strip.addEventListener('touchend', () => strip.classList.remove('on'));

/* click buttons: hold Left to drag */
function holdBtn(el, b) {
  let held = false, timer;
  el.addEventListener('touchstart', e => { e.preventDefault(); el.classList.add('on'); held = false;
    timer = setTimeout(() => { held = true; sendQ({a:'press', b}); buzz(15); }, 350); }, {passive:false});
  el.addEventListener('touchend', e => { e.preventDefault(); el.classList.remove('on'); clearTimeout(timer);
    if (held) sendQ({a:'release', b}); else { sendQ({a:'click', b}); buzz(); } }, {passive:false});
}
holdBtn($('#lc'), 'left'); holdBtn($('#rc'), 'right');

/* ---------- keyboard ---------- */
$('#more').onclick = () => { const o = $('#extra').classList.toggle('open'); $('#more').classList.toggle('on', o); buzz(5); };
const mods = new Set();
const clearMods = () => { mods.clear(); $$('.mod').forEach(m => m.classList.remove('on')); };
function key(k) {
  if (mods.size) { sendQ({a:'hotkey', keys:[...mods, k]}); clearMods(); }
  else sendQ({a:'key', k});
  buzz();
}
$$('.mod').forEach(b => b.onclick = () => {
  const m = b.dataset.m; mods.has(m) ? mods.delete(m) : mods.add(m); b.classList.toggle('on'); buzz(5);
});
$$('[data-k]').forEach(b => b.onclick = () => key(b.dataset.k));
$$('[data-c]').forEach(b => b.onclick = () => {
  const c = b.dataset.c;
  const keys = c === 'SWITCH' ? [MAC ? 'cmd' : 'alt', 'tab'] : c.split(',').map(x => x === 'MOD' ? MOD : x);
  sendQ({a:'hotkey', keys}); clearMods(); buzz();
});

const kb = $('#kb'); let prev = '';
kb.addEventListener('input', () => {
  const v = kb.value; let i = 0;
  while (i < prev.length && i < v.length && prev[i] === v[i]) i++;
  const added = v.slice(i);
  if (mods.size && added.length === 1) {          // e.g. Ctrl + typed letter
    sendQ({a:'hotkey', keys:[...mods, added.toLowerCase()]}); clearMods();
    kb.value = prev; return;
  }
  for (let j = i; j < prev.length; j++) sendQ({a:'key', k:'backspace'});
  if (added) sendQ({a:'type', text:added});
  prev = v;
});
kb.addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); key('enter'); kb.value = ''; prev = ''; }
  else if (e.key === 'Backspace' && kb.value === '') key('backspace');
});
</script></body></html>
"""

ICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#5b8cff"/><stop offset="1" stop-color="#8a6bff"/></linearGradient></defs>
<rect width="192" height="192" rx="44" fill="#0b0d10"/>
<path d="M64 42v100l26-24 18 36 20-9-18-35h36z" fill="url(#g)" stroke="url(#g)" stroke-width="6" stroke-linejoin="round"/>
</svg>"""


# ---------------------------------------------------------------- HTTPS server
class Handler(BaseHTTPRequestHandler):
    timeout = 15  # drop idle connections

    def log_message(self, *args):
        pass  # keep the terminal quiet

    def _reply(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _gate(self, token):
        """Private-network IPs only, not rate-limited, and the right secret token."""
        ip = self.client_address[0]
        try:
            private = ipaddress.ip_address(ip).is_private
        except ValueError:
            private = False
        if not private or blocked(ip):
            self._reply(403)
            return False
        if not token or not same(token, config()["token"]):
            record_fail(ip)
            self._reply(403)
            return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        if not self._gate(parse_qs(url.query).get("t", [""])[0]):
            return
        token = config()["token"]
        if url.path == "/manifest.json":
            self._reply(200, json.dumps({
                "name": "Glide", "short_name": "Glide",
                "start_url": f"/?t={token}", "display": "standalone",
                "background_color": "#0b0d10", "theme_color": "#0b0d10",
                "icons": [{"src": f"/icon.svg?t={token}", "sizes": "any", "type": "image/svg+xml"}],
            }).encode(), "application/manifest+json")
        elif url.path == "/icon.svg":
            self._reply(200, ICON.encode(), "image/svg+xml")
        elif url.path == "/":
            self._reply(200, PAGE.replace("__TOKEN__", token).encode(), "text/html; charset=utf-8")
        else:
            self._reply(404)

    def do_POST(self):
        if urlparse(self.path).path != "/api":
            self._reply(404)
            return
        if not self._gate(self.headers.get("X-Glide-Token", "")):
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = -1
        if not 0 <= n <= MAX_BODY:
            self._reply(413)
            return
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(d, dict):
                raise ValueError
        except ValueError:
            self._reply(400)
            return

        a = d.get("a")
        if a == "pair":
            dev = pair_device()
            if dev:
                self._reply(200, json.dumps({"device": dev}).encode())
            else:
                self._reply(409)  # device limit reached
            return

        dev = self.headers.get("X-Glide-Device", "")
        if not dev or not any(same(dev, x) for x in config()["devices"]):
            self._reply(401)  # unknown phone -> page re-pairs
            return

        if a == "ping":
            self._reply(200, json.dumps({"os": platform.system(), "host": hostname()}).encode())
            return
        try:
            act(a, d)
        except Exception as e:
            print("error:", e)
        self._reply(204)


class Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # failed TLS handshakes, plain-HTTP probes, dropped phones: ignore


def serve():
    ensure_cert()
    config()
    try:
        server = Server(("0.0.0.0", PORT), Handler)
    except OSError:
        print(f"\n  Port {PORT} is busy: Glide is already running (probably started at login),")
        print("  or the old WiFi Mouse is still running.")
        show_link()
        sys.exit(0)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    # handshake happens in the worker thread, so a slow client can't block others
    server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    show_link()
    print("  Running. Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------- firewall (Windows)
FW_RULES = [("Glide (private networks)", "allow", "private"),
            ("Glide (block public networks)", "block", "public")]


def firewall(add=True):
    """Allow Glide on Private networks, block it on Public ones (cafes, hotels...). Needs admin."""
    if platform.system() != "Windows":
        return True
    ok = True
    for name, action, profile in FW_RULES:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                       capture_output=True)
        if add:
            r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
                                "dir=in", f"action={action}", "protocol=TCP", f"localport={PORT}",
                                f"profile={profile}"], capture_output=True)
            ok = ok and r.returncode == 0
    return ok


def firewall_cmd():
    if platform.system() != "Windows":
        print("\n  Only needed on Windows. On Mac/Linux, keep your OS firewall on for public WiFi.\n")
    elif firewall(True):
        print("\n  Firewall rules added: Glide allowed on Private networks, blocked on Public.\n")
    else:
        print("\n  Couldn't add firewall rules. Open a terminal as Administrator and run:")
        print(f"    python \"{SCRIPT}\" --firewall\n")


# ---------------------------------------------------------------- autostart
def startup_paths(name="glide", app_id=APP_ID):
    system = platform.system()
    if system == "Windows":
        folder = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
        return system, os.path.join(folder, f"{name}.vbs")
    if system == "Darwin":
        return system, os.path.expanduser(f"~/Library/LaunchAgents/{app_id}.plist")
    return system, os.path.expanduser(f"~/.config/autostart/{name}.desktop")


def remove_legacy():
    """Remove the old 'WiFi Mouse' startup entry, if any."""
    system = platform.system()
    name = "wifi-mouse" if system not in ("Windows", "Darwin") else "wifi_mouse"
    _, path = startup_paths(name, "com.wifimouse.server")
    if os.path.exists(path):
        if system == "Darwin":
            subprocess.run(["launchctl", "unload", path], capture_output=True)
        os.remove(path)
        print(f"  Removed old WiFi Mouse startup entry ({path}).")
        print("  If WiFi Mouse is still running, log out/in (or end its pythonw process) to free the port.")


def install():
    remove_legacy()
    ensure_cert()
    config()
    system, path = startup_paths()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    py = sys.executable
    if system == "Windows":
        # pythonw = no console window
        pyw = os.path.join(os.path.dirname(py), "pythonw.exe")
        if not os.path.exists(pyw):
            pyw = py
        with open(path, "w") as f:
            f.write(f'CreateObject("WScript.Shell").Run """{pyw}"" ""{SCRIPT}""", 0, False\n')
        subprocess.Popen(["wscript", path])
    elif system == "Darwin":
        with open(path, "w") as f:
            f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{APP_ID}</string>
  <key>ProgramArguments</key><array><string>{py}</string><string>{SCRIPT}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
""")
        subprocess.run(["launchctl", "unload", path], capture_output=True)
        subprocess.run(["launchctl", "load", path])
    else:
        with open(path, "w") as f:
            f.write(f"""[Desktop Entry]
Type=Application
Name=Glide
Exec="{py}" "{SCRIPT}"
X-GNOME-Autostart-enabled=true
NoDisplay=true
""")
        subprocess.Popen([py, SCRIPT], start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("\n  Installed. Glide is running now and will start at every login.")
    print(f"  (startup entry: {path})")
    if system == "Windows":
        firewall_cmd()
    if system == "Darwin":
        print("  Mac: allow this Python in System Settings > Privacy & Security > Accessibility:")
        print(f"       {py}")
    show_link()


def uninstall():
    system, path = startup_paths()
    if system == "Darwin" and os.path.exists(path):
        subprocess.run(["launchctl", "unload", path], capture_output=True)
    firewall(False)
    if os.path.exists(path):
        os.remove(path)
        print("\n  Removed from startup. (Restart or log out to stop the running copy.)\n")
    else:
        print("\n  Wasn't installed.\n")


def show_link():
    ensure_cert()
    token = config()["token"]
    print("\n  Your link (open on your phone, then 'Add to Home Screen'):\n")
    print(f"    https://{local_ip()}:{PORT}/?t={token}")
    print(f"    https://{hostname()}.local:{PORT}/?t={token}   (name-based, works on most iPhones)\n")
    print("  Your phone will warn about the certificate once. Check that its SHA-256")
    print("  fingerprint matches this, then continue:\n")
    print(f"    {fingerprint()}\n")
    print("  Keep this link private: it controls your keyboard and mouse.\n")


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--install" in args:
        install()
    elif "--uninstall" in args:
        uninstall()
    elif "--link" in args:
        show_link()
    elif "--reset" in args:
        config(reset=True)
        print("\n  New link created. The old link and all paired phones no longer work.")
        show_link()
    elif "--firewall" in args:
        firewall_cmd()
    else:
        serve()
