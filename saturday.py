from __future__ import annotations

import argparse
import email
import email.policy
import html
import imaplib
import json
import mimetypes
import os
import random
import re
import shutil
import sqlite3
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parent

# Load .env file manually if it exists
_env_file = ROOT / ".env"
if _env_file.exists():
    try:
        with _env_file.open("r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line or _line.startswith("#"):
                    continue
                if "=" in _line:
                    _key, _val = _line.split("=", 1)
                    os.environ.setdefault(_key.strip(), _val.strip().strip("'\""))
    except OSError:
        pass

WEB_DIR = ROOT / "web"
ASSET_DIR = ROOT / "asset"
DATA_DIR = ROOT / "data"
INCIDENTS_FILE = DATA_DIR / "incidents.json"
BLOCKED_SENDERS_FILE = DATA_DIR / "blocked_senders.json"
REPORT_DIR = DATA_DIR / "reports"
DEFAULT_PORT = 8765
RISK_BLOCK_THRESHOLD = 70
DEFAULT_WHATSAPP_CHAT = "SATURDAY"
WHATSAPP_NOTIFICATION_DB = Path(os.getenv("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "Notifications" / "wpndatabase.db"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def local_now_label() -> str:
    return datetime.now().strftime("%H:%M")


def json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return fallback


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    temp.replace(path)


def new_id(prefix: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{prefix}_{stamp}_{random.randint(100, 999)}"


def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def base_domain(hostname: str) -> str:
    host = hostname.lower().strip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def first_label(domain: str) -> str:
    return domain.split(".", 1)[0].lower()


def deobfuscate(text: str) -> str:
    table = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "@": "a",
            "$": "s",
        }
    )
    return text.lower().translate(table)


def compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def html_escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


KNOWN_BRANDS = {
    "google": {
        "official": "google.com",
        "aliases": ["gmail", "google", "accounts.google"],
        "display": "Google",
    },
    "paypal": {
        "official": "paypal.com",
        "aliases": ["paypal", "pay-pal"],
        "display": "PayPal",
    },
    "microsoft": {
        "official": "microsoft.com",
        "aliases": ["microsoft", "office", "outlook", "live"],
        "display": "Microsoft",
    },
    "amazon": {
        "official": "amazon.com",
        "aliases": ["amazon", "aws"],
        "display": "Amazon",
    },
    "apple": {
        "official": "apple.com",
        "aliases": ["apple", "icloud"],
        "display": "Apple",
    },
    "whatsapp": {
        "official": "whatsapp.com",
        "aliases": ["whatsapp"],
        "display": "WhatsApp",
    },
    "github": {
        "official": "github.com",
        "aliases": ["github", "git-hub"],
        "display": "GitHub",
    },
    "openai": {
        "official": "openai.com",
        "aliases": ["openai", "chatgpt"],
        "display": "OpenAI",
    },
}

KNOWN_BAD_DOMAINS = {
    "g00gle-login.xyz",
    "paypa1-secure.com",
    "micros0ft-security.live",
    "invoice-review.zip",
    "appleid-verify.top",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "xyz",
    "top",
    "click",
    "work",
    "quest",
    "support",
    "live",
    "rest",
}

LOGIN_WORDS = {
    "login",
    "signin",
    "verify",
    "account",
    "secure",
    "security",
    "password",
    "wallet",
    "auth",
    "session",
}

URGENT_WORDS = {
    "urgent",
    "immediately",
    "expires",
    "suspend",
    "suspended",
    "locked",
    "final warning",
    "within 24 hours",
    "act now",
    "unusual activity",
}

MONEY_WORDS = {
    "invoice",
    "payment",
    "refund",
    "wire",
    "bank",
    "payroll",
    "purchase order",
}

CREDENTIAL_WORDS = {
    "password",
    "verify your account",
    "confirm your account",
    "re-enter",
    "login",
    "sign in",
    "2fa",
    "mfa",
}

ATTACHMENT_RISK_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".iso", ".zip", ".rar", ".7z"}


@dataclass
class RiskResult:
    risk_score: int
    reasons: list[str]
    brand: str | None = None
    official_url: str | None = None
    domain: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "brand": self.brand,
            "official_url": self.official_url,
            "domain": self.domain,
        }


class RiskEngine:
    url_pattern = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)

    def official_brand_for_domain(self, domain: str) -> dict[str, Any] | None:
        if not domain:
            return None
        for data in KNOWN_BRANDS.values():
            official = data["official"]
            if domain == official or domain.endswith(f".{official}"):
                return data
        return None

    def score_url(self, url: str) -> RiskResult:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        host = parsed.hostname or url
        domain = base_domain(host)
        label = first_label(domain)
        label_compact = compact(label)
        label_clear = compact(deobfuscate(label))
        domain_compact = compact(domain)
        domain_clear = compact(deobfuscate(domain))
        path_text = f"{parsed.path} {parsed.query}".lower()
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        score = 0
        reasons: list[str] = []
        brand_hit: str | None = None
        official_url: str | None = None

        if domain in KNOWN_BAD_DOMAINS:
            score += 80
            reasons.append("Domain appears in Saturday's local high-risk demo feed")

        if tld in SUSPICIOUS_TLDS:
            score += 12
            reasons.append(f"Unusual or abuse-prone top-level domain: .{tld}")

        if any(ch.isdigit() for ch in label):
            score += 14
            reasons.append("Domain uses number substitutions often seen in impersonation")

        if "-" in label:
            score += 7
            reasons.append("Domain uses hyphenated brand-style wording")

        if len(label) > 24:
            score += 8
            reasons.append("Domain label is unusually long")

        if any(word in path_text for word in LOGIN_WORDS):
            score += 16
            reasons.append("URL path contains login or account-verification language")

        for brand_key, data in KNOWN_BRANDS.items():
            official = data["official"]
            official_label = first_label(official)
            official_label_compact = compact(official_label)
            display = data["display"]

            if domain == official or domain.endswith(f".{official}"):
                if not reasons:
                    reasons.append("Official domain match")
                return RiskResult(0, reasons[:1], display, f"https://{official}", domain)

            similarity = max(
                SequenceMatcher(None, label_compact, official_label_compact).ratio(),
                SequenceMatcher(None, label_clear, official_label_compact).ratio(),
            )
            brand_token_present = any(
                compact(alias) in domain_compact or compact(alias) in domain_clear
                for alias in data["aliases"]
            )

            if (
                (label_clear == official_label_compact and label_compact != official_label_compact)
                or (
                    label_clear.startswith(official_label_compact)
                    and label_compact != official_label_compact
                    and any(word in label_clear for word in LOGIN_WORDS)
                )
            ):
                score += 48
                brand_hit = display
                official_url = f"https://{official}"
                reasons.append(f"Typosquatting detected: looks like {display}")
            elif similarity >= 0.84 and label_compact != official_label_compact:
                score += 38
                brand_hit = display
                official_url = f"https://{official}"
                reasons.append(f"Domain is visually similar to {display}")
            elif brand_token_present and domain != official:
                if any(word in compact(domain) for word in LOGIN_WORDS):
                    score += 34
                    reasons.append(f"Brand plus account-security wording suggests {display} impersonation")
                else:
                    score += 18
                    reasons.append(f"Domain references {display} outside the official domain")
                brand_hit = brand_hit or display
                official_url = official_url or f"https://{official}"

        if not reasons:
            reasons.append("No strong phishing indicators found")

        return RiskResult(clamp(score), reasons, brand_hit, official_url, domain)

    def extract_urls(self, text: str) -> list[str]:
        return [match.group(0).rstrip(").,]") for match in self.url_pattern.finditer(text or "")]

    def score_email(
        self,
        sender: str,
        subject: str,
        body: str,
        attachments: list[str] | None = None,
    ) -> dict[str, Any]:
        attachments = attachments or []
        combined = f"{sender}\n{subject}\n{body}".lower()
        sender_domain_match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", sender)
        sender_domain = base_domain(sender_domain_match.group(1)) if sender_domain_match else ""
        trusted_sender_brand = self.official_brand_for_domain(sender_domain)
        score = 0
        reasons: list[str] = []
        brand_hit: str | None = trusted_sender_brand["display"] if trusted_sender_brand else None
        official_url: str | None = f"https://{trusted_sender_brand['official']}" if trusted_sender_brand else None

        if sender_domain:
            domain_result = self.score_url(sender_domain)
            if domain_result.risk_score >= 35:
                score += min(45, domain_result.risk_score)
                reasons.extend(domain_result.reasons[:2])
                brand_hit = domain_result.brand
                official_url = domain_result.official_url

        for brand_key, data in KNOWN_BRANDS.items():
            display = data["display"]
            official = data["official"]
            mentions_brand = any(alias.lower() in combined for alias in data["aliases"])
            if trusted_sender_brand and data["official"] != trusted_sender_brand["official"]:
                continue
            if mentions_brand and sender_domain and sender_domain != official and not sender_domain.endswith(f".{official}"):
                score += 28
                brand_hit = brand_hit or display
                official_url = official_url or f"https://{official}"
                reasons.append(f"Message references {display}, but sender is not an official {display} domain")
                break

        if any(word in combined for word in URGENT_WORDS):
            score += 14
            reasons.append("Urgent pressure language detected")

        if any(word in combined for word in CREDENTIAL_WORDS):
            score += 18
            reasons.append("Credential or account-verification request detected")

        if any(word in combined for word in MONEY_WORDS):
            score += 10
            reasons.append("Payment or invoice language detected")

        risky_attachments = [
            name for name in attachments if Path(name.lower()).suffix in ATTACHMENT_RISK_EXTENSIONS
        ]
        if risky_attachments:
            score += 22
            reasons.append(f"Risky attachment type: {', '.join(risky_attachments[:2])}")

        url_results = [self.score_url(url) for url in self.extract_urls(body)]
        if url_results:
            top_url = max(url_results, key=lambda item: item.risk_score)
            if top_url.risk_score >= 35:
                score += min(42, top_url.risk_score)
                reasons.append(f"Embedded suspicious link: {top_url.domain or 'unknown domain'}")
                reasons.extend(top_url.reasons[:2])
                brand_hit = brand_hit or top_url.brand
                official_url = official_url or top_url.official_url

        deduped_reasons = []
        for reason in reasons:
            if reason not in deduped_reasons:
                deduped_reasons.append(reason)

        if not deduped_reasons:
            deduped_reasons = ["No high-confidence phishing pattern detected"]

        return {
            "risk_score": clamp(score),
            "reasons": deduped_reasons[:6],
            "brand": brand_hit,
            "official_url": official_url,
            "sender_domain": sender_domain,
        }


class IncidentStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            write_json(self.path, [])
        if not BLOCKED_SENDERS_FILE.exists():
            write_json(BLOCKED_SENDERS_FILE, [])

    def all(self) -> list[dict[str, Any]]:
        with self.lock:
            incidents = read_json(self.path, [])
        return sorted(incidents, key=lambda item: item.get("created_at", ""), reverse=True)

    def save_all(self, incidents: list[dict[str, Any]]) -> None:
        with self.lock:
            write_json(self.path, incidents)

    def add(self, incident: dict[str, Any], dedupe_key: str | None = None) -> dict[str, Any]:
        incidents = self.all()
        if dedupe_key:
            for existing in incidents:
                if existing.get("dedupe_key") == dedupe_key:
                    return existing
        incident.setdefault("id", new_id("inc"))
        incident.setdefault("created_at", utc_now())
        incident.setdefault("time_label", local_now_label())
        incident.setdefault("status", "pending")
        incident.setdefault("action_log", [])
        incident.setdefault("dedupe_key", dedupe_key)
        incidents.append(incident)
        self.save_all(incidents)
        return incident

    def find(self, incident_id: str) -> dict[str, Any] | None:
        for incident in self.all():
            if incident.get("id") == incident_id:
                return incident
        return None

    def update(self, incident_id: str, **updates: Any) -> dict[str, Any] | None:
        incidents = self.all()
        changed: dict[str, Any] | None = None
        for incident in incidents:
            if incident.get("id") == incident_id:
                incident.update(updates)
                changed = incident
                break
        if changed:
            self.save_all(incidents)
        return changed

    def highest_risk(self, kind: str | None = None) -> dict[str, Any] | None:
        incidents = [
            item
            for item in self.all()
            if item.get("status") not in {"archived", "quarantined", "dismissed"}
            and (kind is None or item.get("kind") == kind)
        ]
        if not incidents:
            return None
        return max(incidents, key=lambda item: int(item.get("risk_score", 0)))

    def clear_demo(self) -> int:
        incidents = self.all()
        kept = [item for item in incidents if item.get("source") != "demo"]
        removed = len(incidents) - len(kept)
        self.save_all(kept)
        return removed


class OpenRouterClient:
    def __init__(self) -> None:
        self.api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        self.model = os.getenv("OPENROUTER_MODEL", "").strip()
        self.endpoint = "https://openrouter.ai/api/v1/chat/completions"

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.model)

    def chat(self, system: str, user: str, max_tokens: int = 450) -> str | None:
        if not self.enabled:
            return None

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.25,
            "max_tokens": max_tokens,
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://127.0.0.1:8765",
                "X-Title": "Saturday Digital Safety Assistant",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=18) as response:
                data = json.loads(response.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
        except (urllib.error.URLError, KeyError, IndexError, json.JSONDecodeError, TimeoutError):
            return None


class OnlineSearcher:
    @staticmethod
    def search_duckduckgo(query: str) -> str:
        url = "https://lite.duckduckgo.com/lite/"
        data = urllib.parse.urlencode({"q": query}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                html_data = response.read().decode("utf-8")
                import re
                text = re.sub(r'<[^>]+>', ' ', html_data)
                text = re.sub(r'\s+', ' ', text)
                return text[:2000]
        except Exception:
            return "Search failed."

    @staticmethod
    def fetch_weather(location: str = "Bengaluru") -> str:
        url = f"https://wttr.in/{urllib.parse.quote(location)}?format=3"
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.64.1"})
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.read().decode("utf-8").strip()
        except Exception:
            return "Weather fetch failed."


class AssistantBrain:
    allowed_intents = {
        "SUMMARIZE_INCIDENTS",
        "SHOW_DETAILS",
        "ARCHIVE_EMAIL",
        "QUARANTINE_EMAIL",
        "BLOCK_SENDER",
        "FULL_REPORT",
        "GENERAL_QUERY",
        "NO_OP",
    }

    def __init__(self, store: IncidentStore, ai: OpenRouterClient):
        self.store = store
        self.ai = ai

    def sanitized_incidents(self, limit: int = 8) -> list[dict[str, Any]]:
        clean = []
        for incident in self.store.all()[:limit]:
            clean.append(
                {
                    "id": incident.get("id"),
                    "kind": incident.get("kind"),
                    "title": incident.get("title"),
                    "sender": incident.get("sender"),
                    "url": incident.get("url"),
                    "risk_score": incident.get("risk_score"),
                    "reasons": incident.get("reasons", [])[:5],
                    "status": incident.get("status"),
                    "time_label": incident.get("time_label"),
                }
            )
        return clean

    def local_summary(self, command: str | None = None) -> str:
        incidents = self.store.all()
        if not incidents:
            return "I do not have any incidents yet. Run the demo inbox scan or visit a suspicious test URL to generate the timeline."

        risky = [item for item in incidents if int(item.get("risk_score", 0)) >= 70]
        top = sorted(incidents, key=lambda item: int(item.get("risk_score", 0)), reverse=True)[:3]
        lines = [
            f"Today I tracked {len(incidents)} security event{'s' if len(incidents) != 1 else ''}.",
            f"{len(risky)} of them are high-risk and need attention.",
            "",
        ]
        for index, incident in enumerate(top, 1):
            title = incident.get("title", "Security event")
            risk = incident.get("risk_score", 0)
            reason = (incident.get("reasons") or ["No reason recorded"])[0]
            lines.append(f"{index}. {title} (Risk {risk}) - {reason}")
        lines.append("")
        lines.append("No destructive actions were taken automatically.")
        return "\n".join(lines)

    def explain(self, command: str | None = None) -> str:
        incidents = self.sanitized_incidents()
        if self.ai.enabled and incidents:
            ai_response = self.ai.chat(
                "You are Saturday, a concise local digital safety assistant. Explain risk in plain language. At the end of your summary, if there are high-risk pending emails, ask the user if they would like you to quarantine or delete them. Do not invent incidents. Keep the tone confident and helpful.",
                json.dumps({"command": command or "summarize", "incidents": incidents}, ensure_ascii=False),
                max_tokens=420,
            )
            if ai_response:
                return ai_response
        return self.local_summary(command)

    def parse_intent(self, text: str) -> dict[str, Any]:
        normalized = text.lower().strip()

        if self.ai.enabled:
            incidents = self.sanitized_incidents()
            prompt = {
                "message": text,
                "allowed_intents": sorted(self.allowed_intents),
                "incidents": incidents,
                "rules": [
                    "Return only JSON.",
                    "If the user is just asking for a summary or checking mail, return SUMMARIZE_INCIDENTS.",
                    "If the user says 'yes', 'sure', 'quarantine', or 'do it', return QUARANTINE_EMAIL and pick the highest-risk pending email.",
                    "Use QUARANTINE_EMAIL instead of destructive delete.",
                    "Only target specific emails if the user asks to act on them.",
                    "If the user asks a general question, wants fact checking, or asks for the weather, return GENERAL_QUERY.",
                ],
            }
            response = self.ai.chat(
                "Convert a user's safety command into JSON with keys intent, target, confidence, explanation.",
                json.dumps(prompt, ensure_ascii=False),
                max_tokens=200,
            )
            if response:
                parsed = self._extract_json(response)
                if parsed and parsed.get("intent") in self.allowed_intents:
                    return self._validate_intent(parsed, text)

        if any(phrase in normalized for phrase in ["check my mail", "summarise", "summarize", "what happened", "today", "explain threats", "incident history"]):
            return {"intent": "SUMMARIZE_INCIDENTS", "target": None, "confidence": 0.9, "message": text}
        if "detail" in normalized or "show me" in normalized or "highest" in normalized:
            target = self._resolve_target(normalized)
            return {"intent": "SHOW_DETAILS", "target": target, "confidence": 0.82, "message": text}
        if "delete" in normalized or "remove" in normalized or "quarantine" in normalized:
            target = self._resolve_target(normalized, kind="email")
            return {"intent": "QUARANTINE_EMAIL", "target": target, "confidence": 0.8, "message": text}
        if "archive" in normalized:
            target = self._resolve_target(normalized, kind="email")
            return {"intent": "ARCHIVE_EMAIL", "target": target, "confidence": 0.78, "message": text}
        if "block" in normalized and ("sender" in normalized or "email" in normalized):
            target = self._resolve_target(normalized, kind="email")
            return {"intent": "BLOCK_SENDER", "target": target, "confidence": 0.78, "message": text}
        if "report" in normalized or "full report" in normalized:
            return {"intent": "FULL_REPORT", "target": None, "confidence": 0.86, "message": text}
        return {"intent": "NO_OP", "target": None, "confidence": 0.4, "message": text}

    def execute_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        name = intent.get("intent")
        target = intent.get("target")

        if name == "SUMMARIZE_INCIDENTS":
            return {"ok": True, "intent": name, "message": self.explain("summarize incidents")}

        if name == "GENERAL_QUERY":
            if not self.ai.enabled:
                return {"ok": False, "intent": name, "message": "I need an OpenRouter key to answer general questions."}
            
            location = "Bengaluru"
            lower_msg = intent.get("message", "").lower()
            if "weather" in lower_msg or "hot" in lower_msg or "rain" in lower_msg or "temperature" in lower_msg:
                extract_prompt = "Extract the city name from the user's message. If none is found, just say 'Bengaluru'. Reply with ONLY the city name."
                extracted = self.ai.chat(extract_prompt, intent.get("message", ""), max_tokens=10)
                if extracted and len(extracted) < 30:
                    location = extracted.strip()
                search_context = f"Weather context for {location}:\n{OnlineSearcher.fetch_weather(location)}"
            else:
                search_context = f"Web Search Context:\n{OnlineSearcher.search_duckduckgo(intent.get('message', ''))}"
            
            prompt = (
                "You are Saturday, a digital assistant. Answer the user's question directly based on the provided context. "
                "Do not invent information. If the context does not contain the answer, say you don't know.\n\n"
                f"Context:\n{search_context}"
            )
            ai_response = self.ai.chat(prompt, intent.get("message", ""), max_tokens=600)
            if ai_response:
                return {"ok": True, "intent": name, "message": ai_response}
            return {"ok": False, "intent": name, "message": "I could not fetch an answer."}

        if name == "FULL_REPORT":
            path = self.create_report()
            return {
                "ok": True,
                "intent": name,
                "message": f"Full report generated: {path.name}",
                "report_path": str(path),
            }

        if name in {"SHOW_DETAILS", "ARCHIVE_EMAIL", "QUARANTINE_EMAIL", "BLOCK_SENDER"}:
            if not target:
                return {"ok": False, "intent": name, "message": "I could not safely identify which incident you meant."}
            incident = self.store.find(target)
            if not incident:
                return {"ok": False, "intent": name, "message": "That incident no longer exists in the local timeline."}

            if name == "SHOW_DETAILS":
                return {"ok": True, "intent": name, "message": self.details_text(incident), "incident": incident}

            if incident.get("kind") != "email":
                return {"ok": False, "intent": name, "message": "That action only applies to email incidents in this MVP."}

            if name == "ARCHIVE_EMAIL":
                updated = self._mark(incident, "archived", "Archived locally in Saturday's incident memory")
                return {"ok": True, "intent": name, "message": f"Archived {updated['id']} in Saturday's local record.", "incident": updated}

            if name == "QUARANTINE_EMAIL":
                updated = self._mark(incident, "quarantined", "Quarantined locally; destructive IMAP deletion is disabled for demo safety")
                return {
                    "ok": True,
                    "intent": name,
                    "message": f"I quarantined {updated['id']} locally. I did not permanently delete anything.",
                    "incident": updated,
                }

            if name == "BLOCK_SENDER":
                sender = incident.get("sender", "unknown sender")
                blocked = read_json(BLOCKED_SENDERS_FILE, [])
                if sender not in blocked:
                    blocked.append(sender)
                    write_json(BLOCKED_SENDERS_FILE, blocked)
                updated = self._mark(incident, "sender_blocked", f"Added sender to local block list: {sender}")
                return {"ok": True, "intent": name, "message": f"Blocked sender locally: {sender}", "incident": updated}

        return {
            "ok": False,
            "intent": name or "NO_OP",
            "message": "I can summarize, show details, quarantine, archive, block sender, or create a report.",
        }

    def create_report(self) -> Path:
        incidents = self.store.all()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORT_DIR / f"saturday_report_{stamp}.txt"
        lines = [
            "Saturday Digital Safety Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        for incident in sorted(incidents, key=lambda item: int(item.get("risk_score", 0)), reverse=True):
            lines.extend(
                [
                    f"{incident.get('id')} | Risk {incident.get('risk_score')} | {incident.get('title')}",
                    f"Status: {incident.get('status')}",
                    f"Source: {incident.get('source')} | Type: {incident.get('kind')}",
                    f"Target: {incident.get('sender') or incident.get('url') or incident.get('target')}",
                    "Reasons:",
                ]
            )
            lines.extend([f"- {reason}" for reason in incident.get("reasons", [])])
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def details_text(self, incident: dict[str, Any]) -> str:
        target = incident.get("sender") or incident.get("url") or incident.get("target") or "unknown target"
        reasons = "\n".join(f"- {reason}" for reason in incident.get("reasons", []))
        return (
            f"{incident.get('title', 'Security event')}\n"
            f"Risk: {incident.get('risk_score')}/100\n"
            f"Target: {target}\n"
            f"Status: {incident.get('status')}\n\n"
            f"Why Saturday flagged it:\n{reasons}"
        )

    def _mark(self, incident: dict[str, Any], status: str, action: str) -> dict[str, Any]:
        log = list(incident.get("action_log", []))
        log.append({"at": utc_now(), "action": action})
        return self.store.update(incident["id"], status=status, action_log=log) or incident

    def _resolve_target(self, normalized: str, kind: str | None = None) -> str | None:
        for incident in self.store.all():
            if incident.get("id", "").lower() in normalized:
                return incident.get("id")

        ordinal_map = {"first": 0, "1": 0, "second": 1, "2": 1, "third": 2, "3": 2}
        ranked = [
            item
            for item in sorted(self.store.all(), key=lambda entry: int(entry.get("risk_score", 0)), reverse=True)
            if kind is None or item.get("kind") == kind
        ]
        for key, index in ordinal_map.items():
            if key in normalized and index < len(ranked):
                return ranked[index].get("id")

        highest = self.store.highest_risk(kind=kind)
        return highest.get("id") if highest else None

    def _validate_intent(self, parsed: dict[str, Any], original_text: str = "") -> dict[str, Any]:
        intent = parsed.get("intent")
        target = parsed.get("target")
        if intent in {"ARCHIVE_EMAIL", "QUARANTINE_EMAIL", "BLOCK_SENDER", "SHOW_DETAILS"}:
            if not target or not self.store.find(str(target)):
                target = self._resolve_target("", kind="email" if intent != "SHOW_DETAILS" else None)
        return {
            "intent": intent if intent in self.allowed_intents else "NO_OP",
            "target": target,
            "confidence": float(parsed.get("confidence", 0.5) or 0.5),
            "explanation": parsed.get("explanation"),
            "message": original_text,
        }

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | None:
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?", "", text).strip()
            text = re.sub(r"```$", "", text).strip()
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None


class DemoInbox:
    def __init__(self, store: IncidentStore, risk: RiskEngine):
        self.store = store
        self.risk = risk

    def seed(self) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        demo_messages = [
            {
                "sender": "Google Security <support@g00gle-login.xyz>",
                "subject": "Urgent: unusual activity, verify your account within 24 hours",
                "body": "We detected unusual activity. Sign in now at https://g00gle-login.xyz/accounts/verify to prevent suspension.",
                "attachments": [],
                "minutes_ago": 18,
            },
            {
                "sender": "Billing Team <invoice@invoice-review.zip>",
                "subject": "Final invoice attached - payment due today",
                "body": "Please review the attached invoice and complete payment immediately.",
                "attachments": ["June_Invoice.iso"],
                "minutes_ago": 43,
            },
            {
                "sender": "Microsoft Account <help@micros0ft-security.live>",
                "subject": "Password reset required",
                "body": "Your Microsoft account has been locked. Re-enter your password here: https://micros0ft-security.live/session",
                "attachments": [],
                "minutes_ago": 76,
            },
            {
                "sender": "Campus Events <events@hackathon.local>",
                "subject": "Sponsor booth schedule",
                "body": "Reminder: sponsor demos start after lunch. No action needed.",
                "attachments": [],
                "minutes_ago": 105,
            },
        ]

        created = []
        for message in demo_messages:
            result = self.risk.score_email(
                message["sender"],
                message["subject"],
                message["body"],
                message["attachments"],
            )
            incident = {
                "id": new_id("mail"),
                "kind": "email",
                "source": "demo",
                "title": self._title_for_email(message["subject"], result),
                "sender": message["sender"],
                "subject": message["subject"],
                "snippet": message["body"][:220],
                "risk_score": result["risk_score"],
                "reasons": result["reasons"],
                "brand": result["brand"],
                "official_url": result["official_url"],
                "attachments": message["attachments"],
                "created_at": (now - timedelta(minutes=message["minutes_ago"])).isoformat(timespec="seconds"),
                "time_label": (datetime.now() - timedelta(minutes=message["minutes_ago"])).strftime("%H:%M"),
                "status": "pending",
                "action_log": [],
            }
            created.append(self.store.add(incident, dedupe_key=f"demo:{message['sender']}:{message['subject']}"))

        send_local_notification(
            "Saturday detected suspicious mail",
            f"{sum(1 for item in created if item.get('risk_score', 0) >= 70)} high-risk events were added to the timeline.",
        )
        return created

    @staticmethod
    def _title_for_email(subject: str, result: dict[str, Any]) -> str:
        if result.get("brand"):
            return f"{result['brand']} impersonation attempt"
        if "invoice" in subject.lower():
            return "Suspicious invoice attachment"
        if int(result.get("risk_score", 0)) < 35:
            return "Low-risk email scanned"
        return "Suspicious email detected"


ALLOW_ONCE: dict[str, float] = {}


def allow_url_once(url: str) -> None:
    ALLOW_ONCE[url] = time.time() + 90


def is_allowed_once(url: str) -> bool:
    expires = ALLOW_ONCE.get(url)
    if not expires:
        return False
    if expires < time.time():
        ALLOW_ONCE.pop(url, None)
        return False
    ALLOW_ONCE.pop(url, None)
    return True


def send_local_notification(title: str, message: str) -> None:
    if not sys.platform.startswith("win"):
        return
    safe_title = json.dumps(title)
    safe_message = json.dumps(message)
    script = f"""
try {{
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
  $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
  $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text></text><text></text></binding></visual></toast>")
  $texts = $xml.GetElementsByTagName("text")
  $texts.Item(0).AppendChild($xml.CreateTextNode({safe_title})) | Out-Null
  $texts.Item(1).AppendChild($xml.CreateTextNode({safe_message})) | Out-Null
  $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Saturday").Show($toast)
}} catch {{ }}
"""
    try:
        kwargs: dict[str, Any] = {"timeout": 4, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        pass


@dataclass
class WhatsAppNotification:
    order: int
    arrival_time: int
    title: str
    body: str
    texts: list[str]
    tag: str


class WhatsAppNotificationPoller:
    def __init__(self, chat_name: str, db_path: Path = WHATSAPP_NOTIFICATION_DB):
        self.chat_name = chat_name.strip() or DEFAULT_WHATSAPP_CHAT
        self.chat_key = self.chat_name.casefold()
        self.db_path = db_path
        self.last_order = 0

    def prime(self) -> None:
        self.last_order = self.latest_order()

    def latest_order(self) -> int:
        if not self.db_path.exists():
            return 0

        snapshot = Path(tempfile.gettempdir()) / f"saturday_wpndatabase_prime_{os.getpid()}_{time.time_ns()}.db"
        try:
            shutil.copy2(self.db_path, snapshot)
            with sqlite3.connect(snapshot) as connection:
                row = connection.execute(
                    """
                    select max(n.[Order])
                    from Notification n
                    join NotificationHandler h on h.RecordId = n.HandlerId
                    where lower(h.PrimaryId) like '%whatsapp%'
                    """
                ).fetchone()
            return int((row or [0])[0] or 0)
        except (OSError, sqlite3.Error):
            return 0
        finally:
            try:
                snapshot.unlink(missing_ok=True)
            except OSError:
                pass

    def poll(self) -> list[WhatsAppNotification]:
        events = self._read_since(self.last_order, limit=25)
        for event in events:
            self.last_order = max(self.last_order, event.order)
        return [event for event in events if self.matches_chat(event)]

    def matches_chat(self, event: WhatsAppNotification) -> bool:
        title_key = event.title.casefold()
        return self.chat_key == title_key or self.chat_key in title_key

    def command_from(self, event: WhatsAppNotification) -> str:
        body = event.body or (event.texts[1] if len(event.texts) > 1 else "")
        body = html.unescape(body).strip()
        sender_match = re.match(r"^([^:\n]{1,80}):\s+(.+)$", body, flags=re.DOTALL)
        if sender_match and sender_match.group(1).strip().casefold() not in {"http", "https"}:
            body = sender_match.group(2).strip()
        body = re.sub(r"(?i)^\s*@?saturday\b[:,\-\s]*", "", body).strip()
        if re.search(r"(?i)\b\d+\s+unread messages?\b", body):
            return ""
        return body

    def _read_since(self, since_order: int, limit: int = 25, newest_first: bool = False) -> list[WhatsAppNotification]:
        if not self.db_path.exists():
            return []

        snapshot = Path(tempfile.gettempdir()) / f"saturday_wpndatabase_{os.getpid()}_{time.time_ns()}.db"
        try:
            shutil.copy2(self.db_path, snapshot)
            direction = "desc" if newest_first else "asc"
            safe_limit = max(1, min(int(limit), 100))
            with sqlite3.connect(snapshot) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute(
                    f"""
                    select n.[Order], n.ArrivalTime, n.Tag, n.Payload
                    from Notification n
                    join NotificationHandler h on h.RecordId = n.HandlerId
                    where lower(h.PrimaryId) like '%whatsapp%'
                      and n.PayloadType = 'Xml'
                      and n.[Order] > ?
                    order by n.[Order] {direction}
                    limit ?
                    """,
                    (since_order, safe_limit),
                ).fetchall()
        except (OSError, sqlite3.Error):
            return []
        finally:
            try:
                snapshot.unlink(missing_ok=True)
            except OSError:
                pass

        events = []
        for row in rows:
            texts = self._texts_from_payload(row["Payload"])
            if len(texts) < 2:
                continue
            events.append(
                WhatsAppNotification(
                    order=int(row["Order"]),
                    arrival_time=int(row["ArrivalTime"] or 0),
                    title=texts[0],
                    body=texts[1],
                    texts=texts,
                    tag=str(row["Tag"] or ""),
                )
            )
        return events

    @staticmethod
    def _texts_from_payload(payload: Any) -> list[str]:
        if isinstance(payload, bytes):
            raw = payload.decode("utf-8", errors="ignore")
        else:
            raw = str(payload or "")
        if not raw.strip().startswith("<"):
            return []
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError:
            return []

        texts = []
        for node in root.iter():
            if str(node.tag).rsplit("}", 1)[-1] != "text":
                continue
            value = "".join(node.itertext()).strip()
            if value:
                texts.append(html.unescape(value))
        return texts


class WhatsAppBridge:
    def __init__(
        self,
        brain: AssistantBrain,
        chat_name: str = DEFAULT_WHATSAPP_CHAT,
        poll_seconds: float = 2.0,
        announce: bool = True,
        search_hotkey: str = "ctrl+f",
    ):
        self.brain = brain
        self.chat_name = chat_name.strip() or DEFAULT_WHATSAPP_CHAT
        self.poll_seconds = max(0.8, poll_seconds)
        self.announce = announce
        self.search_hotkey = self._parse_hotkey(search_hotkey)
        self.poller = WhatsAppNotificationPoller(self.chat_name)
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.send_lock = threading.Lock()
        self.pyautogui: Any | None = None

    def start(self) -> None:
        self.poller.prime()
        self.thread = threading.Thread(target=self._run, name="SaturdayWhatsAppBridge", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        print(f"WhatsApp bridge: watching notifications for '{self.chat_name}'.")
        if self.announce:
            self.send_message(
                "Saturday is awake in this WhatsApp demo chat. Try: check my mail, show me the highest risk event, or send me the full report."
            )

        while not self.stop_event.is_set():
            try:
                for event in self.poller.poll():
                    command = self.poller.command_from(event)
                    if not command:
                        continue
                    print(f"WhatsApp command from {event.title}: {command[:90]}")
                    reply = self.answer(command)
                    self.send_message(reply)
            except Exception as exc:
                print(f"WhatsApp bridge paused after an automation error: {exc}")
            self.stop_event.wait(self.poll_seconds)

    def answer(self, message: str) -> str:
        intent = self.brain.parse_intent(message)
        result = self.brain.execute_intent(intent)
        reply = str(result.get("message") or "Done.")
        return f"Saturday:\n{reply}"[:1800]

    def send_message(self, message: str) -> None:
        if not sys.platform.startswith("win"):
            print("WhatsApp bridge only runs on Windows.")
            return

        with self.send_lock:
            gui = self._gui()
            self.focus_chat(gui)
            self._set_clipboard(message)
            gui.hotkey("ctrl", "v")
            time.sleep(0.16)
            gui.press("enter")

    def focus_chat(self, gui: Any) -> None:
        self.launch_whatsapp()
        time.sleep(float(os.getenv("SATURDAY_WHATSAPP_OPEN_WAIT", "2.6")))
        gui.press("esc")
        time.sleep(0.15)
        gui.hotkey(*self.search_hotkey)
        time.sleep(0.25)
        self._set_clipboard(self.chat_name)
        gui.hotkey("ctrl", "v")
        time.sleep(0.25)
        gui.press("enter")
        time.sleep(0.65)

    def launch_whatsapp(self) -> None:
        app_id = os.getenv("SATURDAY_WHATSAPP_APP_ID", "").strip() or self._find_whatsapp_app_id()
        if app_id:
            subprocess.Popen(
                ["explorer.exe", f"shell:AppsFolder\\{app_id}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return

        try:
            os.startfile("whatsapp:")  # type: ignore[attr-defined]
        except OSError:
            subprocess.Popen(["WhatsApp.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _find_whatsapp_app_id(self) -> str | None:
        script = "Get-StartApps | Where-Object {$_.Name -like '*WhatsApp*'} | Select-Object -First 1 -ExpandProperty AppID"
        try:
            kwargs: dict[str, Any] = {
                "capture_output": True,
                "text": True,
                "timeout": 5,
            }
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                **kwargs,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        value = result.stdout.strip().splitlines()
        return value[0].strip() if value else None

    def _gui(self) -> Any:
        if self.pyautogui is None:
            import pyautogui

            pyautogui.PAUSE = 0.08
            self.pyautogui = pyautogui
        return self.pyautogui

    def _set_clipboard(self, text: str) -> None:
        try:
            import pyperclip

            pyperclip.copy(text)
            return
        except Exception:
            pass

        try:
            import tkinter

            root = tkinter.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()
            root.destroy()
        except Exception as exc:
            raise RuntimeError("Could not set clipboard for WhatsApp send") from exc

    @staticmethod
    def _parse_hotkey(value: str) -> tuple[str, ...]:
        parts = tuple(part.strip().lower() for part in value.split("+") if part.strip())
        return parts or ("ctrl", "f")


def scan_imap(store: IncidentStore, risk: RiskEngine, limit: int = 15) -> dict[str, Any]:
    host = os.getenv("SATURDAY_IMAP_HOST", "").strip()
    user = os.getenv("SATURDAY_IMAP_USER", "").strip()
    password = os.getenv("SATURDAY_IMAP_PASSWORD", "").strip()
    folder = os.getenv("SATURDAY_IMAP_FOLDER", "INBOX").strip()
    if not all([host, user, password]):
        return {
            "ok": False,
            "message": "IMAP is not configured. Set SATURDAY_IMAP_HOST, SATURDAY_IMAP_USER, and SATURDAY_IMAP_PASSWORD, or use the demo scan.",
            "created": [],
        }

    created = []
    try:
        with imaplib.IMAP4_SSL(host) as client:
            client.login(user, password)
            client.select(folder)
            status, data = client.search(None, "ALL")
            if status != "OK":
                raise RuntimeError("IMAP search failed")
            ids = data[0].split()[-limit:]
            for message_id in reversed(ids):
                status, fetched = client.fetch(message_id, "(RFC822)")
                if status != "OK" or not fetched or not isinstance(fetched[0], tuple):
                    continue
                raw = fetched[0][1]
                message = email.message_from_bytes(raw, policy=email.policy.default)
                sender = str(message.get("From", "unknown"))
                subject = str(message.get("Subject", "(no subject)"))
                body = extract_email_body(message)
                attachments = [
                    part.get_filename()
                    for part in message.walk()
                    if part.get_filename()
                ]
                result = risk.score_email(sender, subject, body, attachments)
                if result["risk_score"] < 35:
                    continue
                incident = {
                    "id": new_id("mail"),
                    "kind": "email",
                    "source": "imap",
                    "title": f"{result.get('brand') or 'Suspicious'} email detected",
                    "sender": sender,
                    "subject": subject,
                    "snippet": body[:220],
                    "risk_score": result["risk_score"],
                    "reasons": result["reasons"],
                    "brand": result["brand"],
                    "official_url": result["official_url"],
                    "attachments": attachments,
                    "status": "pending",
                    "action_log": [],
                }
                created.append(store.add(incident, dedupe_key=f"imap:{sender}:{subject}:{message_id.decode()}"))
        if created:
            send_local_notification("Saturday scanned your inbox", f"{len(created)} suspicious email events were added.")
        return {"ok": True, "message": f"Scanned IMAP inbox and added {len(created)} suspicious events.", "created": created}
    except Exception as exc:
        return {"ok": False, "message": f"IMAP scan failed: {exc}", "created": created}


def extract_email_body(message: email.message.EmailMessage) -> str:
    if message.is_multipart():
        chunks = []
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    chunks.append(part.get_content())
                except LookupError:
                    pass
        return "\n".join(chunks)
    try:
        return message.get_content()
    except LookupError:
        return ""


class SaturdayApp:
    def __init__(self) -> None:
        self.risk = RiskEngine()
        self.store = IncidentStore(INCIDENTS_FILE)
        self.ai = OpenRouterClient()
        self.brain = AssistantBrain(self.store, self.ai)
        self.demo = DemoInbox(self.store, self.risk)

    def check_url(self, url: str, source: str = "api") -> dict[str, Any]:
        result = self.risk.score_url(url)
        allow_navigation = is_allowed_once(url)
        response = result.as_dict()
        response.update(
            {
                "url": url,
                "allow_navigation": allow_navigation,
                "threshold": RISK_BLOCK_THRESHOLD,
            }
        )

        if result.risk_score >= RISK_BLOCK_THRESHOLD and source in {"extension", "dashboard"}:
            title = (
                f"{result.brand} impersonation blocked"
                if result.brand
                else "Suspicious website blocked"
            )
            self.store.add(
                {
                    "id": new_id("web"),
                    "kind": "web",
                    "source": source,
                    "title": title,
                    "url": url,
                    "target": result.domain,
                    "risk_score": result.risk_score,
                    "reasons": result.reasons,
                    "brand": result.brand,
                    "official_url": result.official_url,
                    "status": "pending",
                    "action_log": [],
                },
                dedupe_key=f"web:{result.domain}:{datetime.now().strftime('%Y-%m-%d')}",
            )
        return response


APP = SaturdayApp()


class Handler(BaseHTTPRequestHandler):
    server_version = "Saturday/0.1"

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_common_headers("application/json")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in {"/", "/dashboard"}:
            self.serve_file(WEB_DIR / "dashboard.html")
            return
        if path == "/warning":
            self.serve_file(WEB_DIR / "warning.html")
            return
        if path == "/api/health":
            self.send_json(
                {
                    "ok": True,
                    "app": "Saturday",
                    "ai_enabled": APP.ai.enabled,
                    "incident_count": len(APP.store.all()),
                    "port": self.server.server_port,
                }
            )
            return
        if path == "/api/incidents":
            self.send_json({"incidents": APP.store.all(), "ai_enabled": APP.ai.enabled})
            return
        if path.startswith("/assets/"):
            self.serve_file(WEB_DIR / path.lstrip("/"))
            return
        if path.startswith("/asset/"):
            self.serve_file(ASSET_DIR / path.removeprefix("/asset/"), root=ASSET_DIR)
            return
        if path in {"/styles.css", "/app.js", "/mascot-viewer.js"}:
            self.serve_file(WEB_DIR / path.lstrip("/"))
            return
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        payload = self.read_json_body()

        if path == "/api/scan-demo":
            created = APP.demo.seed()
            self.send_json({"ok": True, "created": created, "message": f"Added {len(created)} demo incidents."})
            return

        if path == "/api/reset-demo":
            removed = APP.store.clear_demo()
            self.send_json({"ok": True, "message": f"Removed {removed} demo incidents."})
            return

        if path == "/api/scan-mail":
            self.send_json(scan_imap(APP.store, APP.risk, int(payload.get("limit", 15) or 15)))
            return

        if path == "/api/check-url":
            url = str(payload.get("url", "")).strip()
            source = str(payload.get("source", "api")).strip()
            if not url:
                self.send_json({"ok": False, "message": "Missing url"}, status=400)
                return
            self.send_json({"ok": True, **APP.check_url(url, source)})
            return

        if path == "/api/allow-once":
            url = str(payload.get("url", "")).strip()
            if url:
                allow_url_once(url)
            self.send_json({"ok": bool(url), "url": url})
            return

        if path == "/api/explain":
            self.send_json({"ok": True, "message": APP.brain.explain(str(payload.get("command", "")))})
            return

        if path == "/api/command":
            text = str(payload.get("message", "")).strip()
            if not text:
                self.send_json({"ok": False, "message": "Type a command for Saturday."}, status=400)
                return
            intent = APP.brain.parse_intent(text)
            result = APP.brain.execute_intent(intent)
            self.send_json({"ok": result.get("ok", False), "intent": intent, **result})
            return

        if path == "/api/action":
            intent = {
                "intent": str(payload.get("intent", "NO_OP")),
                "target": payload.get("target"),
                "confidence": 1,
            }
            self.send_json(APP.brain.execute_intent(intent))
            return

        self.send_error(404, "Not found")

    def read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        body = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {}

    def send_json(self, data: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_common_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_common_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")

    def serve_file(self, path: Path, root: Path = WEB_DIR) -> None:
        try:
            resolved = path.resolve()
            safe_root = root.resolve()
            if safe_root not in resolved.parents and resolved != safe_root:
                self.send_error(403, "Forbidden")
                return
            if not resolved.exists() or not resolved.is_file():
                self.send_error(404, "Not found")
                return
            raw = resolved.read_bytes()
            content_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
            if resolved.suffix == ".svg":
                content_type = "image/svg+xml"
            elif resolved.suffix == ".glb":
                content_type = "model/gltf-binary"
            self.send_response(200)
            self.send_common_headers(content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except OSError:
            self.send_error(500, "Could not read file")

    def log_message(self, format: str, *args: Any) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {self.address_string()} {format % args}")


def port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) != 0


def choose_port(host: str, preferred: int) -> int:
    for port in range(preferred, preferred + 20):
        if port_available(host, port):
            return port
    return preferred


def main() -> None:
    parser = argparse.ArgumentParser(description="Saturday local digital safety assistant")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--demo", action="store_true", help="Seed the local incident store with demo incidents on launch")
    parser.add_argument("--whatsapp", action="store_true", help="Enable demo WhatsApp Desktop notification bridge")
    parser.add_argument("--whatsapp-chat", default=os.getenv("SATURDAY_WHATSAPP_CHAT", DEFAULT_WHATSAPP_CHAT), help="WhatsApp group/chat name to watch")
    parser.add_argument("--whatsapp-poll-seconds", type=float, default=float(os.getenv("SATURDAY_WHATSAPP_POLL_SECONDS", "2.0")), help="Seconds between notification checks")
    parser.add_argument("--whatsapp-search-hotkey", default=os.getenv("SATURDAY_WHATSAPP_SEARCH_HOTKEY", "ctrl+f"), help="WhatsApp chat search shortcut, for example ctrl+f or ctrl+k")
    parser.add_argument("--whatsapp-no-announce", action="store_true", help="Do not send the startup message to WhatsApp")
    args = parser.parse_args()

    port = choose_port(args.host, args.port)
    if args.demo:
        APP.demo.seed()

    whatsapp_bridge: WhatsAppBridge | None = None
    if args.whatsapp:
        try:
            whatsapp_bridge = WhatsAppBridge(
                APP.brain,
                chat_name=args.whatsapp_chat,
                poll_seconds=args.whatsapp_poll_seconds,
                announce=not args.whatsapp_no_announce,
                search_hotkey=args.whatsapp_search_hotkey,
            )
            whatsapp_bridge.start()
        except Exception as exc:
            print(f"WhatsApp bridge could not start: {exc}")

    server = ThreadingHTTPServer((args.host, port), Handler)
    print("")
    print("Saturday is awake.")
    print(f"Dashboard: http://{args.host}:{port}/")
    print(f"Warning demo: http://{args.host}:{port}/warning?url=https%3A%2F%2Fg00gle-login.xyz%2Faccounts%2Fverify")
    if whatsapp_bridge:
        print(f"WhatsApp bridge: watching the '{args.whatsapp_chat}' chat.")
    if not APP.ai.enabled:
        print("OpenRouter is optional. Set OPENROUTER_API_KEY and OPENROUTER_MODEL to enable cloud explanations.")
    print("Press Ctrl+C to stop.")
    print("")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSaturday stopped.")
    finally:
        if whatsapp_bridge:
            whatsapp_bridge.stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()
