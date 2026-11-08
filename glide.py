"""
Glide - control your laptop's mouse & keyboard from your phone's browser.

See README.md for setup. Quick version:
  Glide.exe                     double-click: installs, starts, shows your link
  python glide.py --install     same, from source (pip install pynput cryptography)
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
FROZEN = getattr(sys, "frozen", False)  # running as a PyInstaller-built executable
SCRIPT = sys.executable if FROZEN else os.path.abspath(__file__)
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


PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def cert_ok():
    """Existing cert has the current hardening (name constraints + serverAuth EKU)?"""
    try:
        from cryptography import x509
    except ImportError:
        return True  # can't inspect; keep what we have
    try:
        with open(CERT, "rb") as f:
            c = x509.load_pem_x509_certificate(f.read())
        c.extensions.get_extension_for_class(x509.NameConstraints)
        c.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        return True
    except (OSError, ValueError, x509.ExtensionNotFound):
        return False


def ensure_cert():
    """Self-signed certificate, made once and kept in ~/.glide/.
    If you install it on your phone as trusted, its name constraints mean it can only ever
    vouch for private-network addresses and this laptop's name, never real websites."""
    if os.path.exists(CERT) and os.path.exists(KEY) and cert_ok():
        return
    host, ip = hostname(), local_ip()
    try:
        import datetime
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        try:  # fallback: openssl on PATH
            os.makedirs(HOME, exist_ok=True)
            nets = ",".join(f"permitted;IP:{n.network_address}/{n.netmask}"
                            for n in map(ipaddress.ip_network, PRIVATE_NETS))
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-nodes", "-keyout", KEY, "-out", CERT, "-days", "825", "-subj", "/CN=Glide",
                 "-addext", f"subjectAltName=DNS:{host}.local,DNS:localhost,IP:{ip}",
                 "-addext", "extendedKeyUsage=serverAuth",
                 "-addext", f"nameConstraints=critical,permitted;DNS:{host}.local,"
                            f"permitted;DNS:localhost,{nets}"],
                check=True, capture_output=True)
            os.chmod(KEY, 0o600)
            return
        except (OSError, subprocess.CalledProcessError):
            sys.exit("\n  Glide needs a TLS certificate. Run:  pip install cryptography\n")

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Glide ({host})")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))  # iOS max for trusted certs
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(f"{host}.local"), x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(f"{host}.local"), x509.DNSName("localhost")]
                + [x509.IPAddress(ipaddress.ip_network(n)) for n in PRIVATE_NETS],
                excluded_subtrees=None), critical=True)
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


# Modifiers the phone may hold down (3-finger app switching holds Alt / Cmd).
HOLDABLE = {KEYS[n] for n in ("alt", "cmd", "ctrl", "shift") if n in KEYS}
HOLD_TIMEOUT = 6     # seconds without hearing from the phone -> let go (no stuck Alt)
held = set()
held_lock = threading.Lock()
last_seen = [time.monotonic()]


def release_held():
    with held_lock:
        for k in held:
            keyboard.release(k)
        held.clear()


def held_watchdog():
    while True:
        time.sleep(0.5)
        if held and time.monotonic() - last_seen[0] > HOLD_TIMEOUT:
            release_held()
        if gamepad["busy"] and time.monotonic() - gamepad["seen"] > PAD_TIMEOUT:
            pad_release()


# ---------------------------------------------------------------- virtual Xbox controller
# Uses vgamepad: the ViGEmBus driver on Windows, uinput on Linux, nothing on macOS.
# The controller is plugged in on first use, so games only see it once the phone opens
# the Controller screen. The phone sends the whole controller state whenever it changes.
PAD_BITS = 0xF7FF   # every XUSB button bit (0x0800 is unused)
PAD_TIMEOUT = 2     # seconds without an update while something is held -> let go
gamepad = {"dev": None, "status": None, "seen": 0.0, "busy": False}
gamepad_lock = threading.Lock()


def log(*args):
    """Errors from the background server (it has no visible window): ~/.glide/glide.log"""
    print(*args)
    try:
        with open(os.path.join(HOME, "glide.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + " ".join(map(str, args)) + "\n")
    except OSError:
        pass


def _patient_attach(vcli):
    """vgamepad gives up if the new pad isn't attached the instant it's added. When that
    happens the pad often attaches a moment later anyway and is left behind as a dead
    controller in an XInput slot, so games read the dead one. Wait for it instead."""
    check = vcli.vigem_target_is_attached
    if getattr(check, "patient", False):
        return

    def wait(dev):
        for _ in range(60):          # up to 3 s
            if check(dev):
                return True
            time.sleep(0.05)
        return False
    wait.patient = True
    vcli.vigem_target_is_attached = wait


def pad_open():
    """Plug in the virtual controller if it isn't yet. Returns "ok" or a message for the phone."""
    if gamepad["dev"] is not None:
        return gamepad["status"]
    if platform.system() == "Darwin":
        gamepad["status"] = "The controller isn't available on macOS."
        return gamepad["status"]
    # a failed attempt can still leave a pad behind: never retry in a tight loop
    if gamepad["status"] not in (None, "ok") and time.monotonic() - gamepad.get("tried", 0) < 10:
        return gamepad["status"]
    gamepad["tried"] = time.monotonic()
    try:
        import vgamepad
        if os.name == "nt":
            import vgamepad.win.vigem_client as vcli
            _patient_attach(vcli)
        gamepad["dev"] = vgamepad.VX360Gamepad()
        gamepad["status"] = "ok"
    except ImportError:
        gamepad["status"] = "Run  pip install vgamepad  on your laptop, then restart Glide."
    except Exception as e:
        log("controller error:", repr(e))
        if os.name != "nt":
            gamepad["status"] = "Glide needs write access to /dev/uinput."
        elif not driver_installed():
            gamepad["status"] = DRIVER_MISSING
        else:
            gamepad["status"] = "Couldn't plug in the controller. Restart Glide on your laptop, then try again."
    return gamepad["status"]


# The ViGEmBus driver installer ships inside the vgamepad package (and so inside Glide.exe).
DRIVER_MISSING = "The controller driver (ViGEmBus) isn't installed on your laptop."
driver_job = {"running": False}


def driver_installed():
    if os.name != "nt":
        return True
    r = subprocess.run(["sc", "query", "ViGEmBus"], capture_output=True, creationflags=0x08000000)
    return r.returncode == 0


def driver_msi():
    import importlib.util
    arch = "x64" if platform.machine().endswith("64") else "x86"
    rel = os.path.join("win", "vigem", "install", arch, f"ViGEmBusSetup_{arch}.msi")
    bases = [os.path.join(getattr(sys, "_MEIPASS", ""), "vgamepad")]
    try:
        spec = importlib.util.find_spec("vgamepad")
        if spec and spec.origin:
            bases.append(os.path.dirname(spec.origin))
    except (ImportError, ValueError):
        pass
    for b in bases:
        if os.path.isfile(os.path.join(b, rel)):
            return os.path.join(b, rel)
    return None


def install_driver():
    """Run the bundled ViGEmBus installer (it asks Windows for admin itself). True if it ends up installed."""
    msi = driver_msi()
    if not msi or driver_job["running"]:
        return False
    driver_job["running"] = True
    try:
        subprocess.run(["msiexec", "/i", msi, "/passive", "/norestart"])
    finally:
        driver_job["running"] = False
    with gamepad_lock:
        gamepad["status"] = None   # next pad message tries again
    return driver_installed()


def driver_setup():
    """Windows setup step: offer to install the controller driver if it's missing."""
    if os.name != "nt" or driver_installed() or not driver_msi():
        return
    try:
        ans = input("\n  Install the controller driver (ViGEmBus) for the phone's Controller tab? [Y/n]: ")
    except (EOFError, RuntimeError):
        return
    if ans.strip().lower() in ("", "y", "yes"):
        print("  Approve the Windows prompt...")
        print("  Controller driver installed." if install_driver()
              else "  Driver not installed. You can install it later from the Controller tab.")


def pad_axis(v, lim):
    """Phone sends -1000..1000 (triggers 0..1000); scale to the controller's range."""
    try:
        return max(-lim, min(lim, round(float(v) * lim / 1000)))
    except (TypeError, ValueError, OverflowError):
        return 0


def pad_set(d):
    with gamepad_lock:
        if pad_open() != "ok":
            return
        gp = gamepad["dev"]
        r = gp.report
        b = d.get("b")
        r.wButtons = b & PAD_BITS if isinstance(b, int) else 0
        r.bLeftTrigger = max(0, pad_axis(d.get("lt"), 255))
        r.bRightTrigger = max(0, pad_axis(d.get("rt"), 255))
        r.sThumbLX = pad_axis(d.get("lx"), 32767)
        r.sThumbLY = pad_axis(d.get("ly"), 32767)
        r.sThumbRX = pad_axis(d.get("rx"), 32767)
        r.sThumbRY = pad_axis(d.get("ry"), 32767)
        gp.update()
        gamepad["busy"] = any((r.wButtons, r.bLeftTrigger, r.bRightTrigger,
                               r.sThumbLX, r.sThumbLY, r.sThumbRX, r.sThumbRY))
        gamepad["seen"] = time.monotonic()


def pad_release():
    with gamepad_lock:
        if gamepad["dev"] is not None and gamepad["busy"]:
            gamepad["dev"].reset()
            gamepad["dev"].update()
            gamepad["busy"] = False


def act(a, d):
    btn = Button.right if d.get("b") == "right" else Button.left
    if a in ("down", "up"):
        k = to_key(d.get("k"))
        if k in HOLDABLE:
            with held_lock:
                if a == "down":
                    keyboard.press(k)
                    held.add(k)
                else:
                    keyboard.release(k)
                    held.discard(k)
        return
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
<link rel="apple-touch-icon" href="/apple-touch-icon.png?t=__TOKEN__">
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
.view{position:absolute;inset:0;padding:4px 14px 12px;display:flex;flex-direction:column;gap:12px;
  opacity:0;pointer-events:none;transform:translateY(8px);transition:opacity .2s,transform .2s}
.view.active{opacity:1;pointer-events:auto;transform:none}
#keys,#media{overflow-y:auto}
#keys>*,#media>*{flex-shrink:0}

/* touchpad */
.padwrap{flex:1;display:flex;gap:10px;min-height:0}
#pad{flex:1;position:relative;overflow:hidden;touch-action:none;border-radius:22px;
  background:
    radial-gradient(circle at 50% 0%,color-mix(in srgb,var(--accent) 8%,transparent),transparent 60%),
    radial-gradient(color-mix(in srgb,var(--text) 7%,transparent) 1.2px,transparent 1.2px) 0 0/22px 22px,
    var(--surface);
  border:1px solid var(--line);transition:border-color .2s,box-shadow .2s}
#pad.drag{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent),0 0 30px color-mix(in srgb,var(--accent) 20%,transparent)}
#hint{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;
  gap:10px;color:var(--muted);font-size:13px;transition:opacity .6s;pointer-events:none}
#hint.gone{opacity:0}
#hint div{display:flex;gap:8px;align-items:center}
#hint kbd{font:600 11px system-ui;background:var(--surface2);border:1px solid var(--line);
  padding:3px 8px;border-radius:7px;color:var(--text)}
.rip{position:absolute;width:70px;height:70px;margin:-35px 0 0 -35px;border-radius:50%;pointer-events:none;
  background:radial-gradient(color-mix(in srgb,var(--accent) 33%,transparent),transparent 70%);animation:rip .5s ease-out forwards}
@keyframes rip{from{transform:scale(.3);opacity:1}to{transform:scale(1.6);opacity:0}}
#strip{width:38px;border-radius:19px;background:var(--surface);border:1px solid var(--line);touch-action:none;
  display:flex;flex-direction:column;align-items:center;justify-content:space-between;padding:14px 0;color:var(--muted)}
#strip i{flex:1;width:2px;margin:10px 0;border-radius:2px;
  background:repeating-linear-gradient(var(--line) 0 6px,transparent 6px 12px)}
#strip.on{border-color:var(--accent);color:var(--accent)}
.clicks{display:grid;grid-template-columns:1fr 1fr;gap:10px;height:64px}
.clicks button{border-radius:var(--r);background:var(--surface);border:1px solid var(--line);
  color:var(--muted);font-size:13px;letter-spacing:.5px;text-transform:uppercase;transition:.1s}
.clicks button:active,.clicks button.on{background:var(--surface2);color:var(--text);transform:scale(.98)}

/* keys */
.field{position:relative}
#kb{width:100%;padding:16px 16px 16px 46px;font-size:16px;border-radius:var(--r);border:1px solid var(--line);
  background:var(--surface);color:var(--text);outline:none;-webkit-user-select:text;user-select:text}
#kb:focus{border-color:var(--accent)}
.field svg{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--muted)}
h6{font-size:11.5px;font-weight:600;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin:6px 4px -4px}
.grid{display:grid;gap:8px}
.g4{grid-template-columns:repeat(4,1fr)}
.g3{grid-template-columns:repeat(3,1fr)}
.k{height:52px;border-radius:14px;background:var(--surface);border:1px solid var(--line);font-size:14px;
  display:flex;align-items:center;justify-content:center;gap:6px;transition:.08s}
.k:active{background:var(--surface2);transform:scale(.96)}
.k small{color:var(--muted);font-size:11px}
.mod.on{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent;color:#fff}
.nav{display:grid;grid-template-columns:repeat(3,1fr);grid-template-rows:52px 52px;gap:8px}
.nav .up{grid-column:2;grid-row:1}
.nav .lf{grid-column:1;grid-row:2}.nav .dn{grid-column:2;grid-row:2}.nav .rt{grid-column:3;grid-row:2}

/* media */
.player{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:34px;min-height:300px}
.transport{display:flex;align-items:center;gap:26px}
.round{width:66px;height:66px;border-radius:50%;background:var(--surface);border:1px solid var(--line);display:grid;place-items:center}
.round:active{transform:scale(.93)}
.play{width:96px;height:96px;background:linear-gradient(135deg,var(--accent),var(--accent2));border:0;
  box-shadow:0 12px 40px color-mix(in srgb,var(--accent) 27%,transparent);color:#fff}
.play svg{width:34px;height:34px;fill:#fff;stroke:none}
.vol{display:flex;gap:12px;width:100%;max-width:340px}
.vol .k{flex:1;height:58px}

/* controller (full screen, landscape) */
#game{position:fixed;inset:0;z-index:8;display:none;background:var(--bg);touch-action:none;
  padding:max(8px,env(safe-area-inset-top)) max(10px,env(safe-area-inset-right)) max(8px,env(safe-area-inset-bottom)) max(10px,env(safe-area-inset-left))}
body.game #game{display:block}
#game button,#game b{background:var(--surface);border:1px solid var(--line);color:var(--muted);font-weight:600;transition:transform .06s}
#game .on{background:var(--surface2);border-color:var(--accent);color:var(--text);transform:scale(.95)}
.gpad{height:100%;display:grid;grid-template-columns:1fr auto 1fr;gap:10px}
.side{position:relative}
.sh{display:flex;gap:8px;height:46px}
.sh button{flex:1;border-radius:16px 16px 10px 10px;font-size:13px}
.stick{position:absolute;--s:min(44vh,21vw);width:var(--s);height:var(--s);border-radius:50%;
  background:radial-gradient(circle,color-mix(in srgb,var(--text) 4%,transparent) 0 38%,transparent 39%),var(--surface);border:1px solid var(--line)}
.side.l .stick{left:2%;top:calc(46px + 6%)}
.side.r .stick{left:4%;bottom:2%}
.stick i{position:absolute;left:50%;top:50%;width:46%;height:46%;margin:-23% 0 0 -23%;border-radius:50%;
  background:linear-gradient(145deg,var(--surface2),var(--surface));border:1px solid var(--line);box-shadow:0 6px 18px #0008;transition:transform .1s}
.stick.on{border-color:var(--accent)}
.stick.on i{transition:none;border-color:var(--accent)}
.dpad{position:absolute;--d:min(38vh,18vw);width:var(--d);height:var(--d);right:4%;bottom:2%}
.dpad b{position:absolute;border-radius:10px}
.dpad b:nth-child(1){left:33%;top:0;width:34%;height:40%}
.dpad b:nth-child(2){left:33%;bottom:0;width:34%;height:40%}
.dpad b:nth-child(3){top:33%;left:0;width:40%;height:34%}
.dpad b:nth-child(4){top:33%;right:0;width:40%;height:34%}
.abxy{position:absolute;--a:min(44vh,20vw);width:var(--a);height:var(--a);right:2%;top:calc(46px + 4%)}
.abxy button{position:absolute;width:36%;height:36%;border-radius:50%;font-size:18px}
#game .y{left:32%;top:0;color:#f5c542} #game .a{left:32%;bottom:0;color:#3ddc97}
#game .x{left:0;top:32%;color:#5b8cff} #game .b{right:0;top:32%;color:#ff5d6c}
#game .abxy .on{border-color:currentColor}
.mid{width:min(120px,18vw);display:flex;flex-direction:column;align-items:center;justify-content:space-between;gap:8px;padding:2px 0}
.gtop{display:flex;align-items:center;gap:10px}
#gdot{width:10px;height:10px;border-radius:50%;background:var(--bad)}
#gdot.on{background:var(--good)}
#game .icon{width:40px;height:40px;border-radius:12px}
.sys{display:flex;flex-direction:column;align-items:center;gap:10px}
.sys div{display:flex;gap:10px}
.sys button{width:40px;height:40px;border-radius:50%;display:grid;place-items:center}
.sys .guide{width:52px;height:52px}
.thumbs{display:flex;gap:8px}
.thumbs button{width:48px;height:36px;border-radius:12px;font-size:12px}
#rot,#gmsg{position:absolute;inset:0;display:none;flex-direction:column;align-items:center;justify-content:center;
  gap:16px;padding:24px;text-align:center;color:var(--muted);background:var(--bg)}
#gmsg{background:color-mix(in srgb,var(--bg) 93%,transparent);z-index:1}
#gmsg.show{display:flex}
#game [hidden]{display:none}
#gmsg p{max-width:360px;color:var(--text)}
#rot svg{width:44px;height:44px;color:var(--accent)}
#rot div,#gmsg div{display:flex;gap:10px}
#game #rot .k,#game #gmsg .k{padding:0 22px;height:46px;border-radius:14px;color:var(--text)}
@media (orientation:portrait){body.game .gpad{display:none} body.game #rot{display:flex}}

/* tab bar */
nav.tabs{display:grid;grid-template-columns:repeat(4,1fr);margin:0 14px calc(10px + env(safe-area-inset-bottom));
  background:var(--surface);border:1px solid var(--line);border-radius:22px;padding:6px}
.tab{display:flex;flex-direction:column;align-items:center;gap:3px;padding:8px 0;border-radius:16px;
  color:var(--muted);font-size:11.5px;transition:.2s}
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
a.row{color:inherit;text-decoration:none}
a.row svg{color:var(--accent);flex:none}
.row span small{display:block;color:var(--muted);font-size:12px;margin-top:2px}
input[type=range]{-webkit-appearance:none;appearance:none;width:150px;height:4px;border-radius:2px;background:var(--line)}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;border-radius:50%;background:var(--accent);border:3px solid var(--surface)}
.sw{width:50px;height:30px;border-radius:15px;background:var(--line);position:relative;transition:.2s;flex:none}
.sw::after{content:"";position:absolute;top:3px;left:3px;width:24px;height:24px;border-radius:50%;background:#fff;transition:.2s}
.sw.on{background:var(--accent)} .sw.on::after{left:23px}
#themes{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.th{width:30px;height:30px;border-radius:50%;border:2px solid var(--line);flex:none}
.th.on{outline:2px solid var(--accent);outline-offset:2px}
</style></head><body>

<header>
  <div class="brand"><span id="dot"></span><div><b>Glide</b><small id="host">Connecting…</small></div></div>
  <button class="icon" id="gear" aria-label="Settings"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg></button>
</header>

<main>
  <!-- TOUCHPAD -->
  <section class="view active" id="padv">
    <div class="padwrap">
      <div id="pad">
        <div id="hint">
          <div><kbd>Tap</kbd> click</div>
          <div><kbd>2-finger tap</kbd> right-click</div>
          <div><kbd>2-finger drag</kbd> scroll</div>
          <div><kbd>3-finger swipe</kbd> switch apps</div>
          <div><kbd>Double-tap &amp; drag</kbd> select / move</div>
        </div>
      </div>
      <div id="strip"><svg viewBox="0 0 24 24"><path d="m18 15-6-6-6 6"/></svg><i></i><svg viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></div>
    </div>
    <div class="clicks"><button id="lc">Left</button><button id="rc">Right</button></div>
  </section>

  <!-- KEYBOARD -->
  <section class="view" id="keys">
    <div class="field">
      <svg viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/></svg>
      <input id="kb" placeholder="Tap to type on your laptop" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" enterkeyhint="send">
    </div>
    <h6>Modifiers</h6>
    <div class="grid g4">
      <button class="k mod" data-m="ctrl">Ctrl</button><button class="k mod" data-m="alt" id="altk">Alt</button>
      <button class="k mod" data-m="shift">Shift</button><button class="k mod" data-m="cmd" id="wink">Win</button>
    </div>
    <h6>Keys</h6>
    <div class="grid g4">
      <button class="k" data-k="esc">Esc</button><button class="k" data-k="tab">Tab</button>
      <button class="k" data-k="delete">Del</button><button class="k" data-k="backspace">⌫</button>
      <button class="k" data-k="home">Home</button><button class="k" data-k="end">End</button>
      <button class="k" data-k="page_up">PgUp</button><button class="k" data-k="page_down">PgDn</button>
    </div>
    <div class="nav">
      <button class="k up" data-k="up">↑</button>
      <button class="k lf" data-k="left">←</button><button class="k dn" data-k="down">↓</button><button class="k rt" data-k="right">→</button>
    </div>
    <button class="k" data-k="enter" style="width:100%">Enter ⏎</button>
    <h6>Shortcuts</h6>
    <div class="grid g3">
      <button class="k" data-c="MOD,c">Copy</button><button class="k" data-c="MOD,v">Paste</button><button class="k" data-c="MOD,x">Cut</button>
      <button class="k" data-c="MOD,z">Undo</button><button class="k" data-c="MOD,a">Select all</button><button class="k" data-c="SWITCH">Switch app</button>
      <button class="k" data-c="MOD,w">Close tab</button><button class="k" data-c="MOD,t">New tab</button><button class="k" data-c="MOD,f">Find</button>
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
  <button class="tab active" data-v="padv"><svg viewBox="0 0 24 24"><rect x="5" y="2" width="14" height="20" rx="7"/><path d="M12 6v4"/></svg>Touchpad</button>
  <button class="tab" data-v="keys"><svg viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/></svg>Keyboard</button>
  <button class="tab" data-v="media"><svg viewBox="0 0 24 24"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>Media</button>
  <button class="tab" data-v="game"><svg viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="6"/><path d="M6 12h4M8 10v4M15 11h.01M18 13h.01"/></svg>Controller</button>
</nav>

<!-- CONTROLLER (virtual Xbox controller on the laptop) -->
<section id="game">
  <div class="gpad">
    <div class="side l">
      <div class="sh grp"><button data-t="lt">LT</button><button data-b="256">LB</button></div>
      <div class="stick" id="ls"><i></i></div>
      <div class="dpad" id="dp"><b data-b="1"></b><b data-b="2"></b><b data-b="4"></b><b data-b="8"></b></div>
    </div>
    <div class="mid">
      <div class="gtop"><span id="gdot"></span><button class="icon gexit" aria-label="Close controller"><svg viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg></button></div>
      <div class="sys grp">
        <button class="guide" data-b="1024" aria-label="Guide"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="7"/></svg></button>
        <div>
          <button data-b="32" aria-label="View"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="11" height="11" rx="2"/><path d="M9 20h11V9"/></svg></button>
          <button data-b="16" aria-label="Menu"><svg viewBox="0 0 24 24"><path d="M5 7h14M5 12h14M5 17h14"/></svg></button>
        </div>
      </div>
      <div class="thumbs grp"><button data-b="64">LS</button><button data-b="128">RS</button></div>
    </div>
    <div class="side r">
      <div class="sh grp"><button data-b="512">RB</button><button data-t="rt">RT</button></div>
      <div class="abxy grp"><button class="y" data-b="32768">Y</button><button class="x" data-b="16384">X</button><button class="b" data-b="8192">B</button><button class="a" data-b="4096">A</button></div>
      <div class="stick" id="rs"><i></i></div>
    </div>
  </div>
  <div id="rot"><svg viewBox="0 0 24 24"><rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 3h4M17 21h-4"/></svg>Turn your phone sideways<div><button class="k gexit">Back</button></div></div>
  <div id="gmsg"><p></p><div><button class="k" id="gfix" hidden>Install on laptop</button><button class="k" id="gretry">Try again</button><button class="k gexit">Back</button></div></div>
</section>

<div id="sheet"><div class="panel">
  <div class="grab"></div>
  <h3>Settings</h3>
  <div class="row"><span>Theme</span><div id="themes"></div></div>
  <div class="row"><span>Pointer speed</span><input type="range" id="s-speed" min="0.5" max="4" step="0.1"></div>
  <div class="row"><span>Scroll speed</span><input type="range" id="s-scroll" min="0.3" max="3" step="0.1"></div>
  <div class="row"><span>Natural scrolling<small>Content follows your fingers</small></span><button class="sw" id="s-natural"></button></div>
  <div class="row"><span>Vibration<small>Feedback on taps (Android)</small></span><button class="sw" id="s-haptics"></button></div>
  <a class="row" href="/glide.crt?t=__TOKEN__" download="glide.crt"><span>Remove "not secure" warning<small>Download Glide's certificate, then install it (see README)</small></span><svg viewBox="0 0 24 24"><path d="M12 3v12m0 0-5-5m5 5 5-5M5 21h14"/></svg></a>
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
const S = Object.assign({speed:1.8, scroll:1, natural:true, haptics:true, theme:'midnight'},
  (() => { try { return JSON.parse(store.get('glide') || '{}'); } catch(e) { return {}; } })());
const save = () => store.set('glide', JSON.stringify(S));
const buzz = (ms=8) => { if (S.haptics && navigator.vibrate) navigator.vibrate(ms); };
['speed','scroll'].forEach(k => { const el = $('#s-'+k); el.value = S[k]; el.oninput = () => { S[k] = +el.value; save(); }; });
['natural','haptics'].forEach(k => { const el = $('#s-'+k); el.classList.toggle('on', S[k]);
  el.onclick = () => { S[k] = !S[k]; el.classList.toggle('on', S[k]); save(); buzz(); }; });
/* ---------- themes: bg, surface, surface2, line, text, muted, accent, accent2 ---------- */
const THEMES = {
  midnight: ['#0b0d10','#14171c','#1b1f26','#262b34','#e9edf3','#7d8694','#5b8cff','#8a6bff'],
  oled:     ['#000000','#0d0e11','#16181c','#23262c','#eef1f5','#7a818c','#5b8cff','#8a6bff'],
  light:    ['#f2f4f8','#ffffff','#e7ebf2','#d6dce6','#151922','#66707d','#3b6cf6','#7b5cf5'],
  ocean:    ['#061317','#0c1e24','#122930','#1d3940','#e2f4f6','#6d9198','#22c3d6','#3b82f6'],
  sunset:   ['#140c0f','#1f1418','#2a1b20','#3a262d','#f6e9ec','#9a7f86','#ff7a59','#ff4f8b'],
  forest:   ['#0a110d','#121c16','#19271f','#24362b','#e6f2ea','#7a9283','#3ddc97','#2bb3a3'],
};
const TVARS = ['bg','surface','surface2','line','text','muted','accent','accent2'];
function theme(name) {
  const t = THEMES[name] || THEMES.midnight;
  TVARS.forEach((v, i) => document.documentElement.style.setProperty('--' + v, t[i]));
  $('meta[name=theme-color]').content = t[0];
  $$('.th').forEach(b => b.classList.toggle('on', b.dataset.t === name));
}
Object.entries(THEMES).forEach(([n, t]) => {
  const b = document.createElement('button');
  b.className = 'th'; b.dataset.t = n; b.title = b.ariaLabel = n[0].toUpperCase() + n.slice(1);
  b.style.background = `linear-gradient(135deg,${t[6]} 0 50%,${t[0]} 50%)`;
  b.onclick = () => { S.theme = n; save(); theme(n); buzz(5); };
  $('#themes').append(b);
});
theme(S.theme);

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
    $$('#dot,#gdot').forEach(d => d.classList.add('on')); $('#host').textContent = 'Connected · ' + j.host;
  } catch(e) {
    $$('#dot,#gdot').forEach(d => d.classList.remove('on'));
    $('#host').textContent = MSG[e] || 'Not connected — is the laptop on?';
  }
  clearTimeout(to);
}
ping(); setInterval(ping, 3000);

/* ---------- tabs ---------- */
$$('.tab').forEach(b => b.onclick = () => {
  if (b.dataset.v === 'game') { openGame(); buzz(5); return; }   // full-screen overlay, not a view
  $$('.tab').forEach(x => x.classList.toggle('active', x === b));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === b.dataset.v));
  if (b.dataset.v !== 'keys') $('#kb').blur();
  buzz(5);
});

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
  if (maxF >= 3) { if (e.touches.length >= 3) swipe3(dx, dy); return; }  // ignore fingers lifting off
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
  if (g3) { if (g3.held) sendQ({a:'up', k:g3.held}); g3 = null; lastTap = 0; }   // lift = pick the app
  else if (dragging) { dragging = false; pad.classList.remove('drag'); setTimeout(() => sendQ({a:'release'}), 60); lastTap = 0; }
  else if (quick && maxF <= 2) { sendQ({a:'click', b: maxF === 2 ? 'right' : 'left'}); buzz(); lastTap = maxF === 1 ? Date.now() : 0; }
  maxF = 0; dragArm = false;
}

document.addEventListener('visibilitychange', () => {   // phone locked / app left mid-swipe
  if (document.hidden && g3 && g3.held) { send({a:'up', k:g3.held}); g3 = null; maxF = 0; }
});

/* 3-finger swipe: left/right = app switcher (Alt+Tab held while fingers stay down),
   up = Task View / Mission Control, down = desktop / App Exposé */
let g3 = null;
const STEP = 70;   // px of sideways swipe per app
function swipe3(dx, dy) {
  if (!g3) g3 = {x:0, y:0, axis:null, held:null};
  g3.x += dx; g3.y += dy;
  if (!g3.axis) {
    if (Math.hypot(g3.x, g3.y) < 30) return;
    g3.axis = Math.abs(g3.x) > Math.abs(g3.y) ? 'h' : 'v';
    if (g3.axis === 'v') {
      const up = g3.y < 0;
      sendQ({a:'hotkey', keys: MAC ? ['ctrl', up ? 'up' : 'down'] : ['cmd', up ? 'tab' : 'd']});
      buzz(15); return;
    }
    g3.held = MAC ? 'cmd' : 'alt';
    sendQ({a:'down', k:g3.held});
    g3.x = Math.sign(g3.x) * STEP;   // first step happens right away
  }
  if (g3.axis !== 'h') return;
  while (Math.abs(g3.x) >= STEP) {
    const right = g3.x > 0;
    sendQ(right ? {a:'key', k:'tab'} : {a:'hotkey', keys:['shift', 'tab']});
    g3.x -= Math.sign(g3.x) * STEP; buzz(6);
  }
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

/* ---------- controller: whole state sent on change, one request in flight ---------- */
// b = XUSB button bits, lt/rt = 0..1000, sticks = -1000..1000 (y up is positive)
const G = {b:0, lt:0, rt:0, lx:0, ly:0, rx:0, ry:0};
const parts = new Map();   // control -> {b, lt, rt} it is pressing
let gOn = false, gOK = false, gBusy = false, gDirty = false, gLast = 0, latch = {b:0, lt:0, rt:0};
const gHeld = () => Object.values(G).some(v => v);

async function gFlush() {
  if (gBusy || !gDirty || !gOK) return;
  gDirty = false; gBusy = true; gLast = Date.now();
  // presses that started and ended while a request was in flight still get sent once
  const o = {a:'pad', ...G, b: G.b | latch.b, lt: Math.max(G.lt, latch.lt), rt: Math.max(G.rt, latch.rt)};
  const again = o.b !== G.b || o.lt !== G.lt || o.rt !== G.rt;
  latch = {b:0, lt:0, rt:0};
  await send(o);
  gBusy = false; if (again) gDirty = true; gFlush();
}
const gPush = () => { gDirty = true; gFlush(); };
setInterval(() => { if (gOn && gHeld() && Date.now() - gLast > 500) gPush(); }, 250);   // laptop lets go after 2s of silence

function gUpdate() {
  let b = 0, lt = 0, rt = 0;
  for (const v of parts.values()) { b |= v.b; lt = Math.max(lt, v.lt); rt = Math.max(rt, v.rt); }
  const nb = b & ~G.b, nlt = lt && !G.lt, nrt = rt && !G.rt;
  if (nb || nlt || nrt) buzz(10);
  latch.b |= nb; if (nlt) latch.lt = lt; if (nrt) latch.rt = rt;
  G.b = b; G.lt = lt; G.rt = rt; gPush();
}

const inside = (t, el, pad=6) => { const r = el.getBoundingClientRect();
  return t.clientX >= r.left-pad && t.clientX <= r.right+pad && t.clientY >= r.top-pad && t.clientY <= r.bottom+pad; };
const onTouch = (el, f) => ['touchstart','touchmove','touchend','touchcancel'].forEach(n =>
  el.addEventListener(n, e => { e.preventDefault(); f(e.targetTouches); }, {passive:false}));

// group of buttons: fingers can slide between them and press two at once
function group(el) {
  const kids = [...el.querySelectorAll('[data-b],[data-t]')];
  onTouch(el, ts => {
    const st = {b:0, lt:0, rt:0};
    for (const k of kids) {
      const on = [...ts].some(t => inside(t, k));
      k.classList.toggle('on', on);
      if (on) { if (k.dataset.t) st[k.dataset.t] = 1000; else st.b |= +k.dataset.b; }
    }
    parts.set(el, st); gUpdate();
  });
}
$$('#game .grp').forEach(group);

// d-pad: direction from the finger's angle, 8-way
function dpad(el) {
  const arms = [...el.children];
  onTouch(el, ts => {
    const r = el.getBoundingClientRect(); let b = 0;
    for (const t of ts) {
      const x = t.clientX - r.left - r.width/2, y = t.clientY - r.top - r.height/2;
      if (Math.hypot(x, y) < r.width * 0.12) continue;   // dead centre
      const a = Math.atan2(y, x) * 180 / Math.PI;         // 0 = right, 90 = down
      if (a > -67.5 && a < 67.5) b |= 8;
      if (a > 22.5 && a < 157.5) b |= 2;
      if (a > 112.5 || a < -112.5) b |= 4;
      if (a > -157.5 && a < -22.5) b |= 1;
    }
    arms.forEach(k => k.classList.toggle('on', !!(b & +k.dataset.b)));
    parts.set(el, {b, lt:0, rt:0}); gUpdate();
  });
}
dpad($('#dp'));

// sticks: full tilt a little inside the rim
function stick(el, xk, yk) {
  const knob = el.querySelector('i');
  onTouch(el, ts => {
    const t = ts[0], r = el.getBoundingClientRect(), R = r.width / 2 * 0.72;
    let x = 0, y = 0;
    if (t) {
      x = (t.clientX - r.left - r.width/2) / R; y = (t.clientY - r.top - r.height/2) / R;
      const m = Math.hypot(x, y); if (m > 1) { x /= m; y /= m; }
      if (!el.classList.contains('on')) buzz(6);
    }
    el.classList.toggle('on', !!t);
    knob.style.transform = `translate(${x*R}px,${y*R}px)`;
    G[xk] = Math.round(x * 1000); G[yk] = Math.round(-y * 1000); gPush();
  });
}
stick($('#ls'), 'lx', 'ly'); stick($('#rs'), 'rx', 'ry');

function gReset() {   // let go of everything on the laptop
  parts.clear(); Object.keys(G).forEach(k => G[k] = 0); latch = {b:0, lt:0, rt:0};
  $$('#game .on').forEach(x => x.classList.remove('on'));
  $$('.stick i').forEach(k => k.style.transform = '');
  gPush();
}

async function gConnect() {
  const m = $('#gmsg'); gOK = false;
  try {
    const r = await post({a:'pad', ...G});
    const j = await r.json(); gOK = j.pad === 'ok';
    m.querySelector('p').textContent = j.pad; $('#gfix').hidden = !j.fix;
  } catch(e) { m.querySelector('p').textContent = 'Not connected — is the laptop on?'; $('#gfix').hidden = true; }
  m.classList.toggle('show', !gOK);
}
$('#gfix').onclick = () => {
  buzz(5); send({a:'padinstall'}); $('#gfix').hidden = true;
  $('#gmsg p').textContent = 'Finish the install on your laptop (approve the Windows prompt), then tap Try again.';
};

function openGame() {
  gOn = true; document.body.classList.add('game'); $('#kb').blur();
  const de = document.documentElement;
  if (de.requestFullscreen) de.requestFullscreen({navigationUI:'hide'})
    .then(() => screen.orientation && screen.orientation.lock && screen.orientation.lock('landscape')).catch(() => {});
  gConnect();
}
function closeGame() {
  gReset(); gOn = false; document.body.classList.remove('game');
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  try { screen.orientation.unlock(); } catch(e) {}
  buzz(5);
}
$$('.gexit').forEach(b => b.onclick = closeGame);
$('#gretry').onclick = () => { buzz(5); gConnect(); };
document.addEventListener('visibilitychange', () => { if (document.hidden && gOn) gReset(); });
</script></body></html>
"""

# PNG icons for the home screen (iOS ignores SVG). Drawn by icons/make_icons.py; bundled into the exe.
ICON_DIR = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "icons")
ICON_FILES = {"icon-192.png", "icon-512.png", "icon-maskable-512.png", "apple-touch-icon.png"}

ICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#5b8cff"/><stop offset="1" stop-color="#8a6bff"/></linearGradient></defs>
<rect width="192" height="192" rx="44" fill="#0b0d10"/>
<path transform="translate(-9 -2)" d="M64 42v100l26-24 18 36 20-9-18-35h36z" fill="url(#g)" stroke="url(#g)" stroke-width="6" stroke-linejoin="round"/>
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
                "icons": [
                    {"src": f"/icon-192.png?t={token}", "sizes": "192x192", "type": "image/png"},
                    {"src": f"/icon-512.png?t={token}", "sizes": "512x512", "type": "image/png"},
                    {"src": f"/icon-maskable-512.png?t={token}", "sizes": "512x512", "type": "image/png",
                     "purpose": "maskable"},
                    {"src": f"/icon.svg?t={token}", "sizes": "any", "type": "image/svg+xml"},
                ],
            }).encode(), "application/manifest+json")
        elif url.path == "/icon.svg":
            self._reply(200, ICON.encode(), "image/svg+xml")
        elif url.path.lstrip("/") in ICON_FILES:
            with open(os.path.join(ICON_DIR, url.path.lstrip("/")), "rb") as f:
                self._reply(200, f.read(), "image/png")
        elif url.path == "/glide.crt":  # install on the phone to remove the "not secure" warning
            with open(CERT) as f:
                der = ssl.PEM_cert_to_DER_cert(f.read())
            self._reply(200, der, "application/x-x509-ca-cert")
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

        last_seen[0] = time.monotonic()  # pings every 3s keep held keys alive
        if a == "ping":
            self._reply(200, json.dumps({"os": platform.system(), "host": hostname()}).encode())
            return
        if a == "pad":
            try:
                pad_set(d)
            except Exception as e:
                print("error:", e)
            self._reply(200, json.dumps({"pad": gamepad["status"],
                                         "fix": gamepad["status"] == DRIVER_MISSING and bool(driver_msi())}).encode())
            return
        if a == "padinstall":   # the laptop shows the installer + a Windows admin prompt
            if not driver_job["running"]:
                threading.Thread(target=install_driver, daemon=True).start()
            self._reply(204)
            return
        try:
            act(a, d)
        except Exception as e:
            print("error:", e)
        self._reply(204)


class Server(ThreadingHTTPServer):
    if os.name == "nt":
        # On Windows SO_REUSEADDR lets a second copy bind the same port; demand exclusive use
        allow_reuse_address = False

        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    def handle_error(self, request, client_address):
        pass  # failed TLS handshakes, plain-HTTP probes, dropped phones: ignore


def running():
    """Is something (normally Glide) already listening on our port?"""
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", PORT)) == 0


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
    threading.Thread(target=held_watchdog, daemon=True).start()
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


def launch_cmd(*args, windowless=False):
    """Command that runs Glide: the executable itself, or python + this script."""
    if FROZEN:
        return [sys.executable, *args]
    py = sys.executable
    if windowless and os.name == "nt":
        pyw = os.path.join(os.path.dirname(py), "pythonw.exe")  # no console window
        py = pyw if os.path.exists(pyw) else py
    return [py, SCRIPT, *args]


def fw_present():
    return all(subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={n}"],
                              capture_output=True).returncode == 0 for n, _, _ in FW_RULES)


def ps(command):
    """Run a PowerShell command without flashing a window. Returns (exit code, stdout)."""
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                       capture_output=True, text=True, creationflags=0x08000000)  # CREATE_NO_WINDOW
    return r.returncode, r.stdout.strip()


def wifi_profile():
    """Windows: (interface index, category, name) of the network Glide is served on."""
    if os.name != "nt":
        return None
    code, out = ps("$i = (Get-NetIPAddress -IPAddress '" + local_ip() + "' -ErrorAction Stop).InterfaceIndex; "
                   "$p = Get-NetConnectionProfile -InterfaceIndex $i | Select-Object -First 1; "
                   "'{0}|{1}|{2}' -f $p.InterfaceIndex, $p.NetworkCategory, $p.Name")
    parts = out.split("|", 2)
    if code != 0 or len(parts) != 3 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1], parts[2]


def network_check(interactive=True):
    """Glide is firewalled on Public networks. If this WiFi is Public, offer to mark it
    Private. Returns the interface index to change, or None."""
    p = wifi_profile()
    if not p or p[1] != "Public":
        return None
    idx, _, name = p
    print(f"\n  Windows has your WiFi '{name}' set to Public, so your phone is blocked.")
    if not interactive:
        print("  If it's your home network, double-click Glide (or run --trust-network) to fix it.\n")
        return None
    print("  Marking it Private lets your phone connect (Windows also allows file and")
    print("  printer sharing on Private networks). Only say yes for a network you trust.")
    try:
        ans = input("  Is this your home network? Mark it Private [Y/n]: ").strip().lower()
    except (EOFError, RuntimeError):
        ans = "n"
    return idx if ans in ("", "y", "yes") else None


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run_elevated(*args):
    """Run Glide as Administrator (Windows UAC prompt) and wait.
    Returns its exit code, or None if the prompt was declined."""
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    exe, *rest = launch_cmd(*args, windowless=True)
    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW), fMask=0x40,  # NOCLOSEPROCESS
                             lpVerb="runas", lpFile=exe,
                             lpParameters=" ".join(f'"{a}"' for a in rest), nShow=0)
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return None
    k32 = ctypes.windll.kernel32
    k32.WaitForSingleObject(info.hProcess, 60000)
    code = wintypes.DWORD()
    k32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    k32.CloseHandle(info.hProcess)
    return code.value


def admin_tasks(args):
    """The part that needs Administrator: firewall rules and/or marking a network Private."""
    ok = True
    if "--firewall" in args:
        ok = firewall(True) and ok
    for a in args:
        if a.startswith("--private="):
            ok = ps(f"Set-NetConnectionProfile -InterfaceIndex {int(a.split('=', 1)[1])} "
                    "-NetworkCategory Private")[0] == 0 and ok
    return ok


def admin_setup(private_idx=None):
    """Windows: add firewall rules and mark the network Private, with at most one UAC prompt."""
    if platform.system() != "Windows":
        return
    args = (["--firewall"] if not fw_present() else []) + \
           ([f"--private={private_idx}"] if private_idx is not None else [])
    if not args:
        return
    if is_admin():
        ok = admin_tasks(args)
    else:
        print("\n  Approve the Windows prompt (needs admin, asked once)...")
        code = run_elevated("--admin", *args)
        if code is None:
            print("  Prompt declined. Double-click Glide again to retry.\n")
            return
        ok = code == 0
    if ok:
        if "--firewall" in args:
            print("  Firewall set: Glide allowed on Private networks, blocked on Public.")
        if private_idx is not None:
            print("  WiFi marked Private. Your phone can connect now.")
    else:
        print("  Something failed. Run as Administrator:  "
              + " ".join(f'"{c}"' for c in launch_cmd("--trust-network")))


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
    cmd = launch_cmd("--run", windowless=True)
    if system == "Windows":
        # Run(..., 0) = hidden window, so even the console .exe runs invisibly
        line = " ".join(c if c.startswith("--") else f'""{c}""' for c in cmd)
        with open(path, "w") as f:
            f.write(f'CreateObject("WScript.Shell").Run "{line}", 0, False\n')
        if not running():
            subprocess.Popen(["wscript", path])
    elif system == "Darwin":
        argv = "".join(f"<string>{c}</string>" for c in cmd)
        with open(path, "w") as f:
            f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{APP_ID}</string>
  <key>ProgramArguments</key><array>{argv}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
""")
        subprocess.run(["launchctl", "unload", path], capture_output=True)
        subprocess.run(["launchctl", "load", path])
    else:
        exec_line = " ".join(c if c.startswith("--") else f'"{c}"' for c in cmd)
        with open(path, "w") as f:
            f.write(f"""[Desktop Entry]
Type=Application
Name=Glide
Exec={exec_line}
X-GNOME-Autostart-enabled=true
NoDisplay=true
""")
        if not running():
            subprocess.Popen(cmd, start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("\n  Installed. Glide is running now and will start at every login.")
    print(f"  (startup entry: {path})")
    if FROZEN:
        print("  Keep Glide in this folder: login startup runs it from here.")
    if system == "Windows":
        admin_setup(network_check())
        driver_setup()
    if system == "Darwin":
        print("  Mac: allow Glide in System Settings > Privacy & Security > Accessibility:")
        print(f"       {cmd[0]}")
    show_link()


def setup():
    """What a double-click on the executable does."""
    _, path = startup_paths()
    if os.path.exists(path) and running():
        print("\n  Glide is installed and running.")
        admin_setup(network_check())
        driver_setup()
        show_link()
    else:
        install()
    try:
        input("  Press Enter to close this window (Glide keeps running)...")
    except (EOFError, RuntimeError):
        pass


def uninstall():
    system, path = startup_paths()
    if system == "Darwin" and os.path.exists(path):
        subprocess.run(["launchctl", "unload", path], capture_output=True)
    if system == "Windows":
        firewall(False)
        left = any(subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={n}"],
                                  capture_output=True).returncode == 0 for n, _, _ in FW_RULES)
        if left:
            run_elevated("--firewall-off")  # removing rules needs admin too
    if os.path.exists(path):
        os.remove(path)
        print("\n  Removed from startup. (Restart or log out to stop the running copy.)\n")
    else:
        print("\n  Wasn't installed.\n")


def _color_ok():
    """ANSI colors only on a real terminal (turns them on in the Windows console)."""
    out = sys.stdout
    if out is None or not out.isatty() or os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            h, mode = k32.GetStdHandle(-11), ctypes.c_uint32()
            if not k32.GetConsoleMode(h, ctypes.byref(mode)):
                return False
            k32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except (AttributeError, OSError):
            return False
    return True


def show_link():
    ensure_cert()
    token = config()["token"]
    on = _color_ok()

    def c(code, text):
        return f"\033[{code}m{text}\033[0m" if on else text

    bold, link, dim, warn, step = (lambda t: c("1", t), lambda t: c("1;4;96", t),
                                   lambda t: c("2", t), lambda t: c("1;93", t),
                                   lambda t: c("1;30;106", f" {t} "))
    bar = c("96", "  " + "=" * 62)
    print(f"\n{bar}\n  {bold('CONNECT YOUR PHONE')}  {dim('(phone and laptop on the same WiFi)')}\n{bar}\n")

    print(f"  {step(1)} {bold('Open this link on your phone:')}\n")
    print(f"      {link(f'https://{local_ip()}:{PORT}/?t={token}')}\n")
    print(dim(f"      iPhone alternative: https://{hostname()}.local:{PORT}/?t={token}") + "\n")

    print(f"  {step(2)} {bold('Get past the one-time \"not secure\" warning:')}\n")
    print("      Android: Advanced > Proceed      iPhone: Show Details > visit this website")
    print("      First check the certificate's SHA-256 fingerprint is exactly:")
    print(f"      {warn(fingerprint())}\n")

    print(f"  {step(3)} {bold('Add it to your home screen:')}\n")
    print(f"      Android (Chrome):  {bold('menu (3 dots) > Add to Home screen')}")
    print(f"      iPhone (Safari):   {bold('Share > Add to Home Screen')}\n")

    print(f"  {c('1;91', 'Keep this link private:')} it controls your keyboard and mouse.\n")


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--install" in args:
        install()
    elif "--uninstall" in args:
        uninstall()
    elif "--admin" in args:
        sys.exit(0 if admin_tasks(args) else 1)  # elevated child of admin_setup()
    elif "--link" in args:
        network_check(interactive=False)
        show_link()
    elif "--trust-network" in args:
        idx = network_check()
        if idx is None and fw_present():
            print("\n  Nothing to fix: this WiFi isn't Public and the firewall rules are in place.\n")
        admin_setup(idx)
    elif "--reset" in args:
        config(reset=True)
        print("\n  New link created. The old link and all paired phones no longer work.")
        show_link()
    elif "--firewall-off" in args:
        firewall(False)
    elif "--run" in args or not FROZEN:
        serve()
    else:
        setup()  # executable double-clicked with no arguments
