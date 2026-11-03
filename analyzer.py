"""Offline URL heuristic analyzer for SENTINEL-X. No network requests are made."""
from __future__ import annotations
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

@dataclass(frozen=True)
class Finding:
    title: str
    detail: str
    points: int
    severity: str
    def to_dict(self):
        return asdict(self)

@dataclass
class Result:
    url: str
    host: str
    scheme: str
    score: int
    level: str
    findings: list[Finding]
    note: str = "Heuristic assessment only; this is not a verdict."
    def to_dict(self):
        return {"url": self.url, "host": self.host, "scheme": self.scheme,
                "score": self.score, "level": self.level,
                "findings": [f.to_dict() for f in self.findings], "note": self.note}
    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

_CONTROL = re.compile(r"[\x00-\x20\x7f]")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
_RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "ml", "cf", "ga", "cam"}
_KEYWORDS = {"login", "verify", "update", "secure", "account", "password", "banking", "wallet", "payment", "signin", "confirm"}

def _parse(raw):
    if not isinstance(raw, str):
        raise ValueError("URL must be text.")
    value = raw.strip()
    if not value or _CONTROL.search(value):
        raise ValueError("URL is empty or contains whitespace/control characters.")
    if len(value) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    if value.startswith("//") or "\\" in value:
        raise ValueError("URL format is not allowed.")
    if "://" not in value:
        value = "https://" + value
    try:
        p = urlsplit(value)
        scheme = p.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        if not p.netloc or not p.hostname:
            raise ValueError("A valid hostname is required.")
        if p.username is not None or p.password is not None:
            raise ValueError("URLs containing username or password are not allowed.")
        port = p.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
        if "\\" in p.path:
            raise ValueError("URL path contains invalid characters.")
        raw_host = p.hostname.rstrip(".")
        try:
            ip = ipaddress.ip_address(raw_host)
        except ValueError:
            ip = None
        if ip is not None:
            if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
                raise ValueError("Local or non-public addresses are not supported.")
            host = ip.compressed
        else:
            try:
                host = raw_host.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("Hostname is invalid.") from exc
            labels = host.split(".")
            if len(host) > 253 or len(labels) < 2 or any(not _LABEL.fullmatch(x) for x in labels) or labels[-1].isdigit():
                raise ValueError("Hostname is invalid.")
        if host == "localhost" or host.endswith(".localhost"):
            raise ValueError("Local hostnames are not supported.")
        return value, host, scheme
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("URL is invalid.") from exc

def analyze_url(url):
    normalized, host, scheme = _parse(url)
    parsed = urlsplit(normalized)
    findings = []
    score = 0
    def add(title, detail, points, severity):
        nonlocal score
        findings.append(Finding(title, detail, points, severity))
        score += points
    if scheme == "http":
        add("Unencrypted connection", "The URL uses HTTP rather than HTTPS.", 25, "medium")
    try:
        ipaddress.ip_address(host)
        add("IP address host", "The URL uses an IP address instead of a domain name.", 45, "high")
    except ValueError:
        pass
    if host in _SHORTENERS:
        add("URL shortener", "The final destination is hidden behind a URL shortener.", 20, "medium")
    if host.split(".")[-1] in _RISKY_TLDS:
        add("Uncommon TLD", "This top-level domain may warrant additional scrutiny.", 15, "low")
    if len(host) >= 45:
        add("Long hostname", "The hostname is unusually long.", 10, "low")
    if host.count("-") >= 3:
        add("Hyphen-heavy hostname", "The hostname contains several hyphens.", 10, "low")
    if any(word in host for word in _KEYWORDS):
        add("Sensitive keyword", "The hostname contains a keyword often seen in account or payment lures.", 10, "low")
    if "xn--" in host:
        add("Internationalized hostname", "The hostname uses IDN punycode; check for look-alike characters.", 15, "medium")
    if len(parsed.query) > 120:
        add("Long query string", "The URL contains a long query string.", 5, "low")
    score = min(100, max(0, score))
    level = "High" if score >= 60 else "Medium" if score >= 30 else "Low" if score > 0 else "Safe"
    return Result(normalized, host, scheme, score, level, findings)
