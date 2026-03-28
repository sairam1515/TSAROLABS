import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, quote
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
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$")


def q_enc(q: str) -> str:
    return quote(q, safe="")


def normalize_handle(value: str) -> str:
    v = value.strip()
    if v.startswith("@"):
        return v[1:]
    return v


def parse_intel_request(body: dict):
    first = str(body.get("firstName", "")).strip()[:80]
    last = str(body.get("lastName", "")).strip()[:80]
    keywords = str(body.get("keywords", "")).strip()[:200]
    identifiers = body.get("identifiers") or {}
    emails = identifiers.get("emails") or []
    iocs = identifiers.get("iocs") or []
    if not isinstance(emails, list):
        emails = []
    if not isinstance(iocs, list):
        iocs = []
    emails = [str(e).strip().lower() for e in emails if str(e).strip()]
    iocs = [str(v).strip() for v in iocs if str(v).strip()]
    emails = [e for e in emails if EMAIL_RE.match(e)][:5]
    iocs = iocs[:25]

    if not first and not last and not keywords and len(emails) == 0 and len(iocs) == 0:
        return None, "Provide at least a name, context, an email, or IOCs."

    subject_name = build_subject_name(first, last)
    observables = [{"type": classify_ioc(v), "value": v} for v in iocs]
    return (
        {
            "first": first,
            "last": last,
            "keywords": keywords,
            "emails": emails,
            "iocs": iocs,
            "subject_name": subject_name,
            "observables": observables,
        },
        None,
    )


def collect_handles(observables: list) -> list:
    seen = set()
    out = []
    for o in observables:
        if o.get("type") != "username":
            continue
        raw = str(o.get("value", "")).strip()
        if not raw:
            continue
        norm = normalize_handle(raw)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append({"raw": raw, "normalized": norm})
    return out[:10]


def email_local_parts(emails: list) -> list:
    out = []
    seen = set()
    for e in emails:
        local = e.split("@", 1)[0]
        if local and local not in seen:
            seen.add(local)
            out.append(local)
    return out[:5]


def build_digital_footprint(parsed: dict) -> dict:
    keywords = parsed["keywords"]
    emails = parsed["emails"]
    observables = parsed["observables"]
    subject_name = parsed["subject_name"]

    handles = collect_handles(observables)
    locals_ = email_local_parts(emails)

    parts = []
    if subject_name and subject_name != "Unknown":
        parts.append(subject_name)
    if keywords:
        parts.append(keywords)
    full_q = " ".join(parts).strip()
    if not full_q and emails:
        full_q = " ".join(redact_email(e) for e in emails)

    suggested = []
    if full_q:
        suggested.append(
            {
                "category": "Open web",
                "label": "General web search (Google)",
                "description": "Broad open-web starting point; verify results carefully.",
                "url": f"https://www.google.com/search?q={q_enc(full_q)}",
            }
        )
        suggested.append(
            {
                "category": "Open web",
                "label": "General web search (DuckDuckGo)",
                "description": "Alternative search index; useful for corroboration.",
                "url": f"https://duckduckgo.com/?q={q_enc(full_q)}",
            }
        )

    if subject_name and subject_name != "Unknown":
        nq = f"{subject_name} {keywords} news".strip()
        suggested.append(
            {
                "category": "News / press",
                "label": "News and press mentions",
                "description": "Public articles referencing the name and context you supplied.",
                "url": f"https://www.google.com/search?q={q_enc(nq)}",
            }
        )

    site_queries = []
    if subject_name and subject_name != "Unknown":
        site_queries.extend(
            [
                {
                    "platform": "LinkedIn (public pages only)",
                    "query": f"site:linkedin.com/in {subject_name} {keywords}".strip(),
                    "description": "Filtered web search for public profile URLs; confirm identity before use.",
                    "url": f"https://www.google.com/search?q={q_enc('site:linkedin.com/in ' + subject_name + ' ' + keywords)}",
                },
                {
                    "platform": "X (Twitter)",
                    "query": f"(site:x.com OR site:twitter.com) {subject_name} {keywords}".strip(),
                    "description": "Public posts/handles that mention the name; many false positives possible.",
                    "url": f"https://www.google.com/search?q={q_enc('(site:x.com OR site:twitter.com) ' + subject_name + ' ' + keywords)}",
                },
                {
                    "platform": "Instagram",
                    "query": f"site:instagram.com {subject_name} {keywords}".strip(),
                    "description": "Public bios/usernames; does not confirm the account is operated by the subject.",
                    "url": f"https://www.google.com/search?q={q_enc('site:instagram.com ' + subject_name + ' ' + keywords)}",
                },
                {
                    "platform": "Facebook",
                    "query": f"site:facebook.com {subject_name} {keywords}".strip(),
                    "description": "Public pages; respect platform terms and privacy settings.",
                    "url": f"https://www.google.com/search?q={q_enc('site:facebook.com ' + subject_name + ' ' + keywords)}",
                },
                {
                    "platform": "GitHub",
                    "query": f"site:github.com {subject_name} {keywords}".strip(),
                    "description": "Developer presence and public repos if any.",
                    "url": f"https://www.google.com/search?q={q_enc('site:github.com ' + subject_name + ' ' + keywords)}",
                },
            ]
        )

    for h in handles:
        hn = h["normalized"]
        q_username = f"\"{hn}\" {keywords} profile".strip()
        site_queries.append(
            {
                "platform": "Username (open web)",
                "query": q_username,
                "description": "Reuse of handles is common; corroborate with other signals.",
                "url": f"https://www.google.com/search?q={q_enc(q_username)}",
            }
        )
        site_queries.append(
            {
                "platform": "GitHub by handle",
                "query": f"site:github.com {hn}",
                "description": "Search for the exact handle on GitHub.",
                "url": f"https://www.google.com/search?q={q_enc('site:github.com ' + hn)}",
            }
        )

    for lp in locals_:
        q_local = f"\"{lp}\" {keywords}".strip()
        site_queries.append(
            {
                "platform": "Email local-part hint",
                "query": q_local,
                "description": "People sometimes reuse email prefixes as usernames; verify independently.",
                "url": f"https://www.google.com/search?q={q_enc(q_local)}",
            }
        )

    if keywords:
        site_queries.append(
            {
                "platform": "Context + public presence",
                "query": f"{subject_name} {keywords}".strip(),
                "description": "Combine name/location/employer hints for open-web profiles and directories.",
                "url": f"https://www.google.com/search?q={q_enc(f'{subject_name} {keywords}')}",
            }
        )

    site_queries = site_queries[:24]

    return {
        "ok": True,
        "generated_at": now_iso(),
        "summary": (
            "Digital footprint module: curated open-web search links and checks. "
            "It does not scrape social networks or assert account ownership."
        ),
        "identity": {
            "display_name": subject_name,
            "context": keywords,
            "emails_redacted": [redact_email(e) for e in emails],
        },
        "handles": handles,
        "suggested_searches": suggested,
        "site_specific_queries": site_queries,
        "verification_checklist": [
            "Treat every hit as unverified until you corroborate with a second independent public source.",
            "Watch for name collisions — especially common given names and reused handles.",
            "Do not infer home address or phone numbers; only record what is explicitly public and lawful to use.",
            "Respect platform terms of service, rate limits, and local privacy regulations.",
        ],
        "limitations": [
            "No API guarantees — results depend on search engines and what is publicly indexed.",
            "Private, friends-only, or deleted content will not appear.",
            "This tool does not access the dark web or closed forums.",
        ],
    }


def classify_ioc(value: str) -> str:
    v = value.strip()
    if not v:
        return "unknown"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"
    if EMAIL_RE.match(v.lower()):
        return "email"
    if IP_RE.match(v):
        return "ip"
    if DOMAIN_RE.match(v.lower()):
        return "domain"
    if v.startswith("@") or (len(v) <= 60 and re.match(r"^[A-Za-z0-9._-]{3,60}$", v)):
        return "username"
    return "unknown"


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
        if path not in ("/api/intel", "/api/footprint"):
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

        parsed, err = parse_intel_request(body)
        if err:
            self._set_headers(400)
            self.wfile.write(json.dumps({"ok": False, "error": err}).encode("utf-8"))
            return

        if path == "/api/footprint":
            resp = build_digital_footprint(parsed)
            self._set_headers(200)
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        subject_name = parsed["subject_name"]
        observables = parsed["observables"]
        emails = parsed["emails"]
        keywords = parsed["keywords"]
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
            "observables": observables,
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

