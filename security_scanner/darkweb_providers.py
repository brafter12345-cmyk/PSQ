"""
Provider-agnostic dark-web / leak-data adapter.

The existing scanner pipeline reads `cats.intelx.{total_results, paste_count,
leak_count, darkweb_count, recent_results, score, issues, status}`. All
downstream consumers — report renderer, dashboard, Executive Summary Deck
Phase 4, Plain-Language Summary, credential-risk classifier in
checkers_threats.py — already speak that schema.

This module defines a `DarkWebChecker` that delegates to one or more
back-end providers (Snusbase, LeakCheck, WhiteIntel, IntelX) and emits the
same `cats.intelx.*` shape so nothing downstream changes.

USAGE
-----
    from darkweb_providers import DarkWebChecker
    result = DarkWebChecker().check(domain="phishield.com")
    cats["intelx"] = result   # exact same shape as before

ENV VARS
--------
    DARKWEB_PROVIDER          snusbase | leakcheck | whiteintel | intelx | multi
                              (default: "intelx" for backward compatibility)
    SNUSBASE_API_KEY          if provider in (snusbase, multi)
    LEAKCHECK_API_KEY         if provider in (leakcheck, multi)
    WHITEINTEL_API_KEY        if provider in (whiteintel, multi)
    INTELX_API_KEY            if provider in (intelx, multi)   [already exists]

SWITCHING PROVIDERS
-------------------
Change `DARKWEB_PROVIDER` in Render env vars and redeploy — no code change.
Use "multi" during pilot to compare counts from all configured providers
(results are merged, deduplicated by name+source, then categorised).
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

# WS0: route the dark-web providers through the per-provider seam. Clients add no
# retry (max_attempts=1, so IntelX's own poll loop is unchanged) and return None on
# a failed request instead of raising — mapped to each query()'s error result.
from providers import INTELX, SNUSBASE, LEAKCHECK, WHITEINTEL


# ---------------------------------------------------------------------------
# Normalised record / result shape
# ---------------------------------------------------------------------------

@dataclass
class DarkWebRecord:
    """A single hit normalised across providers."""
    category: str          # "darkweb" | "paste" | "leak"
    name: str              # display name (e.g. "leaks/exampleCo_2024-08-15.txt")
    source: str            # provider-specific source ("Stealer Logs", "Pastebin", "ALIEN_TXTBASE")
    type_label: str        # short type for display ("Stealer log", "Paste", "Document")
    date: str = ""         # ISO YYYY-MM-DD if available
    provider: str = ""     # which provider returned it ("snusbase", "intelx", etc.)


@dataclass
class ProviderResult:
    """What a single provider returns from a query before normalisation."""
    records: list = field(default_factory=list)   # list[DarkWebRecord]
    status: str = "completed"                      # "completed" | "no_api_key" | "auth_failed" | "error"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class DarkWebProvider:
    """Subclass per back-end provider."""
    name: str = "abstract"
    env_key_var: str = ""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get(self.env_key_var)

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def query(self, domain: str, emails: Optional[list] = None) -> ProviderResult:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Concrete providers
# ---------------------------------------------------------------------------

class IntelXProvider(DarkWebProvider):
    """Existing IntelX implementation, refactored into the adapter shape.
    Identical API calls and response handling as `checkers_threats.IntelXChecker`."""
    name = "intelx"
    env_key_var = "INTELX_API_KEY"
    API_URL = "https://free.intelx.io"
    # Requested-and-displayed cap; the free API may over-return, so truncate to
    # this same value (mirrors checkers_threats.IntelXChecker.MAX_RESULTS).
    MAX_RESULTS = 40

    # Media-type code → our normalised category
    _MEDIA_TO_CATEGORY = {1: "paste", 2: "paste", 13: "darkweb"}
    _MEDIA_TO_TYPE = {1: "Paste", 2: "Paste", 5: "Email", 13: "Darkweb", 14: "Document"}

    # Infostealer-log signatures — stealer dumps are served as generic text
    # (media != 13) so without this they all fall into the "leak" bucket and
    # darkweb_count stays 0 even for genuine criminal-forum harvest.
    # review-by: 2026-12-02
    _STEALER_TOKENS = (
        "stealer", "redline", "raccoon", "vidar", "lumma",
        "_default.txt", " default.txt", "/default.txt", "autofill",
        "passwords.txt", "cookies.txt", "credit_cards", "screenshot",
    )

    @classmethod
    def _category_for(cls, rec: dict, media: int) -> str:
        cat = cls._MEDIA_TO_CATEGORY.get(media)
        if cat:
            return cat
        name = (rec.get("name") or "").lower()
        bucket = (rec.get("bucket") or "").lower()
        if any(b in bucket for b in ("darknet", "logs", "stealer")) or \
           any(tok in name for tok in cls._STEALER_TOKENS):
            return "darkweb"
        return "leak"

    def query(self, domain, emails=None):
        if not self.is_configured():
            return ProviderResult(status="no_api_key")
        try:
            r = INTELX.post(f"{self.API_URL}/intelligent/search",
                json={"term": domain, "maxresults": self.MAX_RESULTS, "timeout": 5, "sort": 4, "media": 0},
                headers={"X-Key": self.api_key}, timeout=15)
            if r is None:
                return ProviderResult(status="error", error="no response")
            if r.status_code == 401:
                return ProviderResult(status="auth_failed")
            if r.status_code != 200:
                return ProviderResult(status="error", error=f"HTTP {r.status_code}")
            sid = r.json().get("id")
            if not sid:
                return ProviderResult()
            time.sleep(3)
            records_raw = []
            for _ in range(3):
                r2 = INTELX.get(f"{self.API_URL}/intelligent/search/result",
                    params={"id": sid}, headers={"X-Key": self.api_key}, timeout=10)
                if r2 is None or r2.status_code != 200:
                    break
                data = r2.json()
                records_raw.extend(data.get("records", []))
                if data.get("status") in (1, 2, 4):
                    break
                time.sleep(2)
            # Truncate to the requested cap (the free API may over-return).
            records_raw = records_raw[:self.MAX_RESULTS]
            recs = []
            for rec in records_raw:
                media = rec.get("media", 0)
                recs.append(DarkWebRecord(
                    category=self._category_for(rec, media),
                    name=(rec.get("name") or "Unknown")[:80],
                    source=rec.get("bucket", "intelx"),
                    type_label=self._MEDIA_TO_TYPE.get(media, rec.get("typeh", "Unknown")),
                    date=(rec.get("date") or "")[:10],
                    provider=self.name,
                ))
            return ProviderResult(records=recs)
        except Exception as e:
            return ProviderResult(status="error", error=str(e))


class SnusbaseProvider(DarkWebProvider):
    """Snusbase — primary replacement. Domain-based search across breach +
    stealer-log tables. Docs: https://docs.snusbase.com/

    Endpoint:  POST /data/search
    Auth:      header  Auth: sb<28-char-key>
    Body:      {"terms": [<domain>], "types": ["_domain"], "wildcard": false}
    Rate lim:  2,048 req/day on standard tier
    """
    name = "snusbase"
    env_key_var = "SNUSBASE_API_KEY"
    API_URL = "https://api.snusbase.com/data/search"

    def query(self, domain, emails=None):
        if not self.is_configured():
            return ProviderResult(status="no_api_key")
        try:
            r = SNUSBASE.post(self.API_URL,
                json={"terms": [domain], "types": ["_domain"], "wildcard": False},
                headers={"Auth": self.api_key, "Content-Type": "application/json"},
                timeout=20)
            if r is None:
                return ProviderResult(status="error", error="no response")
            if r.status_code == 401 or r.status_code == 403:
                return ProviderResult(status="auth_failed")
            if r.status_code != 200:
                return ProviderResult(status="error", error=f"HTTP {r.status_code}")
            data = r.json()
            recs = []
            # Snusbase shape: {"results": {<table_name>: [<row>, ...], ...}}
            for table_name, rows in (data.get("results") or {}).items():
                # Heuristic: tables containing "STEALER" or "LOGS" → darkweb
                # bucket; everything else is a credential leak.
                is_stealer = any(tag in table_name.upper() for tag in
                                  ("STEALER", "LOG", "MALWARE", "INFOSTEAL"))
                category = "darkweb" if is_stealer else "leak"
                for row in (rows or []):
                    recs.append(DarkWebRecord(
                        category=category,
                        name=(row.get("email") or row.get("username")
                              or row.get("url") or table_name)[:80],
                        source=table_name,
                        type_label="Stealer log" if is_stealer else "Credential leak",
                        date=(row.get("lastip_date") or row.get("regdate") or "")[:10],
                        provider=self.name,
                    ))
            return ProviderResult(records=recs)
        except Exception as e:
            return ProviderResult(status="error", error=str(e))


class LeakCheckProvider(DarkWebProvider):
    """LeakCheck Pro — secondary blend source for corporate-domain breach
    monitoring. Docs: https://wiki.leakcheck.io/en/api/api-v2-pro

    Endpoint:  GET /v2/query/<domain>?type=domain
    Auth:      header  X-API-Key: <key>
    """
    name = "leakcheck"
    env_key_var = "LEAKCHECK_API_KEY"
    API_URL = "https://leakcheck.io/api/v2/query"

    def query(self, domain, emails=None):
        if not self.is_configured():
            return ProviderResult(status="no_api_key")
        try:
            r = LEAKCHECK.get(f"{self.API_URL}/{domain}",
                params={"type": "domain", "limit": 100},
                headers={"X-API-Key": self.api_key}, timeout=20)
            if r is None:
                return ProviderResult(status="error", error="no response")
            if r.status_code in (401, 403):
                return ProviderResult(status="auth_failed")
            if r.status_code != 200:
                return ProviderResult(status="error", error=f"HTTP {r.status_code}")
            data = r.json()
            recs = []
            for hit in (data.get("result") or []):
                # LeakCheck source field tells us breach name; "origin" is
                # sometimes "darknet" or "combolist" — map accordingly.
                origin = (hit.get("origin") or "").lower()
                if "darknet" in origin or "combolist" in origin or "stealer" in origin:
                    category, type_label = "darkweb", "Stealer/combolist"
                elif "paste" in origin:
                    category, type_label = "paste", "Paste"
                else:
                    category, type_label = "leak", "Breach"
                recs.append(DarkWebRecord(
                    category=category,
                    name=(hit.get("email") or hit.get("username") or "Unknown")[:80],
                    source=hit.get("source", {}).get("name", "LeakCheck"),
                    type_label=type_label,
                    date=(hit.get("source", {}).get("date") or "")[:10],
                    provider=self.name,
                ))
            return ProviderResult(records=recs)
        except Exception as e:
            return ProviderResult(status="error", error=str(e))


class WhiteIntelProvider(DarkWebProvider):
    """WhiteIntel — stealer-log focused upgrade path. Docs:
    https://docs.whiteintel.io/whiteintel-api-doc/whiteintel-api-v2/corporate-leaks-api

    Endpoint:  POST /get_corporate_leaks.php
    Auth:      body field  apikey=<key>
    Body:      {"apikey": "...", "domain": "<domain>"}
    Rate lim:  500 calls/day on Threat Intel tier
    """
    name = "whiteintel"
    env_key_var = "WHITEINTEL_API_KEY"
    API_URL = "https://api.whiteintel.io/v2/get_corporate_leaks.php"

    def query(self, domain, emails=None):
        if not self.is_configured():
            return ProviderResult(status="no_api_key")
        try:
            r = WHITEINTEL.post(self.API_URL,
                json={"apikey": self.api_key, "domain": domain},
                timeout=20)
            if r is None:
                return ProviderResult(status="error", error="no response")
            if r.status_code in (401, 403):
                return ProviderResult(status="auth_failed")
            if r.status_code != 200:
                return ProviderResult(status="error", error=f"HTTP {r.status_code}")
            data = r.json()
            recs = []
            # WhiteIntel response shape (per docs): {"data": [{employee, password,
            # source_url, computer_name, infection_date, ...}, ...]}
            for hit in (data.get("data") or []):
                recs.append(DarkWebRecord(
                    category="darkweb",   # all WhiteIntel hits are stealer-log origin
                    name=(hit.get("employee") or hit.get("email") or "Unknown")[:80],
                    source=hit.get("source_url") or hit.get("source") or "WhiteIntel",
                    type_label="Stealer log",
                    date=(hit.get("infection_date") or "")[:10],
                    provider=self.name,
                ))
            return ProviderResult(records=recs)
        except Exception as e:
            return ProviderResult(status="error", error=str(e))


# ---------------------------------------------------------------------------
# Aggregator — emits the existing cats.intelx.* schema
# ---------------------------------------------------------------------------

_PROVIDERS = {
    "intelx":     IntelXProvider,
    "snusbase":   SnusbaseProvider,
    "leakcheck":  LeakCheckProvider,
    "whiteintel": WhiteIntelProvider,
}


class DarkWebChecker:
    """Drop-in replacement for IntelXChecker. Emits the same cats.intelx.*
    shape regardless of which provider(s) backed it.

    Provider selection (precedence):
      1. constructor argument `provider_names: list[str]`
      2. env var DARKWEB_PROVIDER (single name or "multi")
      3. default "intelx"
    """

    def __init__(self, provider_names: Optional[list] = None):
        if provider_names is None:
            env = os.environ.get("DARKWEB_PROVIDER", "intelx").strip().lower()
            if env == "multi":
                provider_names = list(_PROVIDERS.keys())
            else:
                provider_names = [env]
        self.providers = [_PROVIDERS[n]() for n in provider_names if n in _PROVIDERS]

    def check(self, domain: str, emails: Optional[list] = None) -> dict:
        """Returns the same shape as the legacy IntelXChecker.check() output."""
        result = {
            "status": "completed",
            "total_results": 0,
            "paste_count": 0,
            "leak_count": 0,
            "darkweb_count": 0,
            "recent_results": [],
            "score": 100,
            "issues": [],
            "providers_used": [],   # NEW — observability
        }

        configured = [p for p in self.providers if p.is_configured()]
        if not configured:
            result["status"] = "no_api_key"
            return result

        all_records: list[DarkWebRecord] = []
        errors = []
        for p in configured:
            pr = p.query(domain, emails=emails)
            result["providers_used"].append({"name": p.name, "status": pr.status,
                                              "count": len(pr.records)})
            if pr.status == "completed":
                all_records.extend(pr.records)
            elif pr.error:
                errors.append(f"{p.name}: {pr.error}")

        # Deduplicate across providers by (name, source, category)
        seen = set()
        deduped = []
        for r in all_records:
            key = (r.name.lower(), r.source.lower(), r.category)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)

        result["total_results"] = len(deduped)
        for r in deduped:
            if r.category == "paste":
                result["paste_count"] += 1
            elif r.category == "darkweb":
                result["darkweb_count"] += 1
            else:
                result["leak_count"] += 1
            if len(result["recent_results"]) < 10:
                result["recent_results"].append({
                    "name": r.name, "type": r.type_label,
                    "media": r.source, "date": r.date,
                })

        # Scoring — identical formula to legacy IntelXChecker
        if result["darkweb_count"] > 0:
            result["score"] = max(0, 100 - result["darkweb_count"] * 15)
            result["issues"].append(
                f"{result['darkweb_count']} dark web mention(s) found — "
                "credentials or data may be actively traded on criminal forums.")
        if result["paste_count"] > 5:
            result["score"] = max(0, result["score"] - result["paste_count"] * 3)
            result["issues"].append(
                f"{result['paste_count']} paste site mention(s) — "
                "data has been shared on public paste sites (Pastebin, etc.).")
        if result["total_results"] > 0 and not result["issues"]:
            result["issues"].append(
                f"{result['total_results']} reference(s) found in dark web and leak databases.")

        if errors:
            result["partial_errors"] = errors

        return result


# ---------------------------------------------------------------------------
# Wiring (sketch) — how to plug this into the existing scanner
# ---------------------------------------------------------------------------
# In scanner.py (or wherever IntelXChecker is instantiated today), replace:
#
#     intelx_data = IntelXChecker().check(domain, api_key=intelx_api_key)
#     cats["intelx"] = intelx_data
#
# with:
#
#     from darkweb_providers import DarkWebChecker
#     cats["intelx"] = DarkWebChecker().check(domain, emails=staff_emails)
#
# That's the entire integration. Provider selection is env-driven; downstream
# (report renderer, dashboard cat_intelx card, Executive Summary Deck Phase 4,
# credential_risk classifier) is unchanged because the output schema is
# byte-identical to the legacy IntelXChecker.
#
# For the pilot phase, set DARKWEB_PROVIDER=multi in Render env vars to run
# all configured providers in parallel. The `providers_used` field in the
# response reveals exactly which provider contributed what — use that to
# decide which subscription(s) to keep.
