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

## Demo Notes

- WhatsApp automation is intentionally not the primary command path because Desktop UI automation is fragile during live judging.
- The dashboard command console is the reliable MVP path.
- The browser warning uses original runner-themed art and visual language instead of official Subway Surfers assets.
- Incidents are stored in `data/incidents.json`.
- Reports are generated in `data/reports`.
