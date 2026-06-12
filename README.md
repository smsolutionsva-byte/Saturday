# Saturday - Agentic Digital Safety Assistant

Saturday is a Windows-focused hackathon MVP for a proactive local digital safety assistant. It scans email-like content, scores suspicious URLs and senders with local rules first, stores incidents in JSON, explains findings, and gives the user safe natural-language actions.

The build intentionally avoids a heavy stack: Python 3.12, local JSON files, vanilla HTML/CSS/JS, and an unpacked browser extension.

## Quick Start

```powershell
cd C:\Users\Red\Downloads\SATURDAY
python .\saturday.py --demo
```

Open:

```text
http://127.0.0.1:8765/
```

Try these commands in the dashboard:

```text
check my mail
show me the highest risk event
quarantine that email
block sender
send me the full report
```

## Browser Guard

1. Start Saturday with `python .\saturday.py --demo`.
2. Open Chrome or Edge.
3. Go to `chrome://extensions` or `edge://extensions`.
4. Enable Developer Mode.
5. Choose Load unpacked.
6. Select `C:\Users\Red\Downloads\SATURDAY\extension`.
7. Visit `https://g00gle-login.xyz/accounts/verify` to see the warning flow.

The extension asks the local Python server to score every top-level navigation. If risk is 70 or higher, it redirects the tab to Saturday's warning screen.

## Optional OpenRouter

Saturday works without OpenRouter. Without a key, it uses deterministic local summaries and local intent parsing.

To enable OpenRouter explanations and command parsing:

```powershell
$env:OPENROUTER_API_KEY="your-key"
$env:OPENROUTER_MODEL="your-free-openrouter-model"
python .\saturday.py --demo
```

The AI is not the detection engine. Saturday sends only sanitized incident facts such as risk score, sender, URL, and reasons.

## Optional IMAP Scan

Set these environment variables before clicking Scan IMAP:

```powershell
$env:SATURDAY_IMAP_HOST="imap.example.com"
$env:SATURDAY_IMAP_USER="you@example.com"
$env:SATURDAY_IMAP_PASSWORD="app-password"
$env:SATURDAY_IMAP_FOLDER="INBOX"
python .\saturday.py
```

For demo safety, Saturday does not permanently delete real email. The "delete" action is implemented as local quarantine in the incident store.

## Optional WhatsApp Demo Bridge

Saturday can mirror the dashboard command console into a WhatsApp Desktop group for hackathon demos.

1. Install/sign in to WhatsApp Desktop from the Microsoft Store.
2. Create or open a group named `SATURDAY`.
3. Keep WhatsApp notifications enabled for that group in Windows and WhatsApp.
4. Start Saturday:

```powershell
python .\saturday.py --demo --whatsapp --whatsapp-chat "SATURDAY"
```

When someone messages the `SATURDAY` group, Saturday reads the Windows notification, opens WhatsApp Desktop, focuses that group, and replies with the same local command brain used by the website chat.

Useful tweaks:

```powershell
python .\saturday.py --demo --whatsapp --whatsapp-chat "SATURDAY" --whatsapp-no-announce
$env:SATURDAY_WHATSAPP_SEARCH_HOTKEY="ctrl+k"
```

If WhatsApp changes its search shortcut on the demo laptop, set `SATURDAY_WHATSAPP_SEARCH_HOTKEY` to the shortcut that focuses chat search.

## Demo Notes

- WhatsApp automation is available as an optional wow-factor bridge, but the dashboard command console remains the reliable MVP path if desktop UI focus changes during judging.
- The browser warning uses original runner-themed art and visual language instead of official Subway Surfers assets.
- Incidents are stored in `data/incidents.json`.
- Reports are generated in `data/reports`.
