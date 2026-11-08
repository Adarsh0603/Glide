# Glide

Use your phone as a touchpad and keyboard for your laptop over WiFi. No app needed, just the phone's browser.

## Setup

```
pip install pynput cryptography
python glide.py --install
```

This starts Glide now and at every login, then prints your link.

1. Open the link on your phone (same WiFi as the laptop).
2. The phone warns about the certificate once. Check that the SHA-256 fingerprint matches the one Glide printed, then continue.
3. Add the page to your home screen.

- **Windows:** the firewall rules need admin rights. If `--install` couldn't add them, run `python glide.py --firewall` from an Administrator terminal.
- **macOS:** allow Python under System Settings > Privacy & Security > Accessibility.

## Commands

| Command | What it does |
|---|---|
| `python glide.py` | Run in this terminal |
| `python glide.py --install` | Start at every login |
| `python glide.py --uninstall` | Stop starting at login |
| `python glide.py --link` | Show your link |
| `python glide.py --reset` | New link; unpairs all phones |
| `python glide.py --firewall` | Windows: allow on Private networks, block on Public |

## Using it

- **1 finger drag:** move the cursor
- **Tap:** left click
- **2-finger tap:** right click
- **2-finger drag** or the side strip: scroll
- **Double-tap and drag**, or hold **Left**: drag or select

The text box under the touchpad types on the laptop. You can keep the phone keyboard open while you use the touchpad. The ☰ button shows modifier keys, arrows and shortcuts.

## Security

- Traffic is encrypted with HTTPS. The self-signed certificate is in `~/.glide/`.
- The link holds a secret token. At most 3 phones can pair with it. `--reset` revokes the link and all paired phones.
- Only private-network addresses are accepted.
- After 10 wrong tokens, that IP is blocked for 10 minutes.
- Anyone with your link can control your keyboard. Keep it private.
