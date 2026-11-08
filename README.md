# Glide

Use your phone as a touchpad and keyboard for your laptop over WiFi. No app needed, just the phone's browser.

## Setup

**Windows, no Python needed:** put `Glide.exe` in a permanent folder and double-click it. It starts Glide now and at every login, then shows your link. Double-click it again any time to see the link.

**From source:**

```
pip install pynput cryptography
python glide.py --install
```

**Build the exe yourself:** run `powershell -ExecutionPolicy Bypass -File build.ps1`. The output is `dist\Glide.exe`.

Then:

1. Open the link on your phone (same WiFi as the laptop).
2. The phone warns about the certificate once. Check that the SHA-256 fingerprint matches the one Glide printed, then continue.
3. Add the page to your home screen.

- **Windows:** Glide is blocked on networks Windows calls Public. If your WiFi is Public, setup asks whether it's your home network and marks it Private. It asks for admin rights once (UAC prompt) to do that and to add the firewall rules. SmartScreen or antivirus may warn about the unsigned exe. Click "More info" > "Run anyway".
- **macOS:** allow Python under System Settings > Privacy & Security > Accessibility.

## Removing the "not secure" warning

Glide's certificate is self-signed, so the phone can't verify it and shows a warning. The connection is still encrypted. To get rid of the warning, open Settings (gear icon) > **Remove "not secure" warning**, then:

- **Android:** Settings > Security > More security settings > Encryption & credentials > Install a certificate > **CA certificate**, then pick `glide.crt`. The exact menu names vary by phone.
- **iPhone:** open the link in Safari, download the certificate, then go to Settings > Profile Downloaded > Install. Then Settings > General > About > Certificate Trust Settings, and turn on "Glide".

The certificate is restricted: it can only vouch for private-network addresses (`10.*`, `172.16-31.*`, `192.168.*`) and this laptop's `.local` name, never for real websites. The warning comes back if the laptop's IP address changes. To prevent that, reserve the IP in your router, or use the `.local` link.

## Commands

Use `Glide.exe` in place of `python glide.py` if you have the exe.

| Command | What it does |
|---|---|
| `python glide.py` | Run in this terminal (`Glide.exe --run`) |
| `python glide.py --install` | Start at every login |
| `python glide.py --uninstall` | Stop starting at login |
| `python glide.py --link` | Show your link |
| `python glide.py --reset` | New link; unpairs all phones |
| `python glide.py --trust-network` | Windows: mark this WiFi Private and fix the firewall rules |

## Using it

- **1 finger drag:** move the cursor
- **Tap:** left click
- **2-finger tap:** right click
- **2-finger drag** or the side strip: scroll
- **Double-tap and drag**, or hold **Left**: drag or select
- **3-finger swipe left/right:** switch apps (Alt+Tab). Keep swiping to move along, lift to pick.
- **3-finger swipe up:** Task View (Mission Control on Mac)
- **3-finger swipe down:** show desktop (App Exposé on Mac)

The text box under the touchpad types on the laptop. You can keep the phone keyboard open while you use the touchpad. The ☰ button shows modifier keys, arrows and shortcuts.

## Security

- Traffic is encrypted with HTTPS. The self-signed certificate is in `~/.glide/`.
- The link holds a secret token. At most 3 phones can pair with it. `--reset` revokes the link and all paired phones.
- Only private-network addresses are accepted.
- After 10 wrong tokens, that IP is blocked for 10 minutes.
- Anyone with your link can control your keyboard. Keep it private.
