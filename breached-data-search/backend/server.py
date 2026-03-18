import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone


def load_dotenv(dotenv_path: str) -> None:
    """
    Minimal .env loader (KEY=VALUE lines).
    Does not overwrite already-set environment variables.
    """
    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("'").strip('"')
                if key and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        return


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_subject_name(first: str, last: str) -> str:
    name = f"{first} {last}".strip()
    return name if name else "Unknown"


def redact_email(email: str) -> str:
    if "@" not in email:
        return "[redacted-email]"
    user, domain = email.split("@", 1)
    if len(user) <= 1:
        return f"***@{domain}"
    return f"{user[0]}***@{domain}"


def compute_risk(matches_count: int) -> dict:
    if matches_count >= 5:
        return {"level": "high", "score": 85, "rationale": "Multiple breach exposures reported by licensed sources."}
    if matches_count >= 1:
        return {"level": "medium", "score": 55, "rationale": "At least one breach exposure reported by licensed sources."}
    return {"level": "low", "score": 15, "rationale": "No breach exposures found from configured sources."}


def recommended_sources() -> list:
    return [
        {
            "name": "Have I Been Pwned (HIBP)",
            "type": "breach_exposure",
            "what_it_verifies": "Whether a provided email appears in known breaches (metadata only).",
            "how_to_enable": "Set HIBP_API_KEY in backend environment."
        }
    ]


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def hibp_breached_account(email: str) -> dict:
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        return {"enabled": False, "email": email, "matches": [], "error": None}

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true"
    req = Request(
        url,
        method="GET",
        headers={
            "hibp-api-key": api_key,
            "user-agent": "IndiaTrace/0.1 (local)",
            "accept": "application/json",
        },
    )

    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        if e.code == 404:
            return {"enabled": True, "email": email, "matches": [], "error": None}
        try:
            body = e.read().decode("utf-8")
            msg = json.loads(body).get("message") or f"HIBP request failed ({e.code})"
        except Exception:
            msg = f"HIBP request failed ({e.code})"
        return {"enabled": True, "email": email, "matches": [], "error": msg}
    except URLError as e:
        return {"enabled": True, "email": email, "matches": [], "error": f"HIBP network error: {e.reason}"}
    except Exception as e:
        return {"enabled": True, "email": email, "matches": [], "error": f"HIBP error: {e}"}

    matches = []
    if isinstance(data, list):
        for b in data:
            breach_name = b.get("Name") or b.get("Title") or "Unknown breach"
            first_seen = b.get("BreachDate") or b.get("AddedDate") or ""
            domain = b.get("Domain") or ""
            matches.append(
                {
                    "source": "HIBP",
                    "type": "breach_exposure",
                    "identifier_matched": {"type": "email", "value_redacted": redact_email(email)},
                    "breach_name": breach_name,
                    "first_seen": first_seen,
                    "confidence": 90,
                    "verification": {
                        "evidence_level": "level_1",
                        "notes": "Match reported by HIBP breachedaccount endpoint (truncateResponse=true).",
                    },
                    "url_reference": f"https://{domain}" if domain else "",
                }
            )

    return {"enabled": True, "email": email, "matches": matches, "error": None}


class Handler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._set_headers(200)
            self.wfile.write(json.dumps({"ok": True, "time": now_iso()}).encode("utf-8"))
            return
        self._set_headers(404)
        self.wfile.write(json.dumps({"ok": False, "error": "Not found"}).encode("utf-8"))

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/intel":
            self._set_headers(404)
            self.wfile.write(json.dumps({"ok": False, "error": "Not found"}).encode("utf-8"))
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            self._set_headers(400)
            self.wfile.write(json.dumps({"ok": False, "error": "Invalid JSON body"}).encode("utf-8"))
            return

        first = str(body.get("firstName", "")).strip()[:80]
        last = str(body.get("lastName", "")).strip()[:80]
        keywords = str(body.get("keywords", "")).strip()[:200]
        identifiers = body.get("identifiers") or {}
        emails = identifiers.get("emails") or []
        if not isinstance(emails, list):
            emails = []
        emails = [str(e).strip().lower() for e in emails if str(e).strip()]
        # validate + cap
        emails = [e for e in emails if EMAIL_RE.match(e)][:5]

        if not first and not last and not keywords and len(emails) == 0:
            self._set_headers(400)
            self.wfile.write(json.dumps({"ok": False, "error": "Provide at least a name, context, or an email identifier."}).encode("utf-8"))
            return

        subject_name = build_subject_name(first, last)
        checks = []
        matches = []
        errors = []

        for email in emails:
            hibp = hibp_breached_account(email)
            checks.append({"name": "HIBP", "enabled": hibp["enabled"], "status": "error" if hibp["error"] else "ok"})
            if hibp["error"]:
                errors.append({"source": "HIBP", "message": hibp["error"]})
            matches.extend(hibp["matches"])

        risk = compute_risk(len(matches))

        resp = {
            "ok": True,
            "generated_at": now_iso(),
            "subject": {"name": subject_name, "context": keywords},
            "risk_overview": risk,
            "matches": matches,
            "recommended_next_steps": [
                "Enable MFA on all accounts and rotate passwords for affected services.",
                "If an organization/domain: enable domain-wide breach monitoring with a licensed provider.",
                "Review public profiles for overshared personal information.",
                "If you suspect active impersonation: document evidence and report to the platform(s).",
            ],
            "limitations": [
                "This app does not crawl Tor/I2P or private communities.",
                "Results depend on which licensed APIs you configure (e.g., HIBP).",
                "No sensitive leak contents are returned; output is metadata-only and redacted.",
            ],
            "recommended_sources": recommended_sources(),
            "checks": checks,
            "errors": errors,
        }

        self._set_headers(200)
        self.wfile.write(json.dumps(resp).encode("utf-8"))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    load_dotenv(os.path.join(here, ".env"))

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8787"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"IndiaTrace backend running on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()

