#!/usr/bin/env python3
"""
H1DorkCollector v2.3 — Automated HackerOne Report Link Collector
=================================================================
Collects ALL disclosed HackerOne report links for a given vulnerability class.

Engines:
  1. hackerone-api  → official HackerOne REST API (free key, recommended)
  2. google-cse     → Google Custom Search API (100 req/day free)
  3. serpapi        → SerpAPI (100 searches/month free)
  4. hackerone-gql  → HackerOne GraphQL (no key, may be unstable)

v2.3 changelog:
  * all output and comments in English
  * small-result-set fix: a partial page is no longer misreported as a
    server page-size cap (totals < 50 now end cleanly in one pass)
  * v2.2: incremental checkpoint (Ctrl+C/crash-safe), resume on re-run,
    per-weakness queries, case-insensitive query dedup
  * v2.1: ascending-sort sanity check before claiming completeness

Observed HackerOne API behavior (undocumented, learned the hard way):
  * page[size] is server-capped at 50 — requesting more shrinks your
    reachable pagination window
  * simple single-term queries paginate to their natural end (1854 items seen)
  * OR-group queries cwe:("A" OR "B" ...) truncate silently around ~950-1000
  * the cwe: filter matches weakness NAMES, case-insensitively
  * cwe:<number> is not supported by the endpoint
"""

import argparse
import json
import os
import sys
import time
from datetime import date, datetime, timedelta

try:
    import requests
except ImportError:
    import subprocess
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "requests",
         "--break-system-packages", "-q"],
        stdout=subprocess.DEVNULL,
    )
    import requests


# ─────────────────────────────────────────────────────────────
# CWE presets (exact H1 weakness-taxonomy names) + CWE numbers
# ─────────────────────────────────────────────────────────────
CWE_PRESETS: dict[str, list[str]] = {
    # NOTE: the cwe: filter is CASE-INSENSITIVE — keep exactly one
    # spelling per name, or you get duplicate queries.
    "xss": [
        "Cross-Site Scripting (XSS)",
        "Cross-site Scripting (XSS) - DOM",
        "Cross-site Scripting (XSS) - Generic",
        "Cross-site Scripting (XSS) - Reflected",
        "Cross-site Scripting (XSS) - Stored",
    ],
    "sqli": ["SQL Injection"],
    "ssrf": ["Server-Side Request Forgery (SSRF)"],
    "idor": ["Insecure Direct Object Reference (IDOR)"],
    "rce": ["Remote Code Execution", "Code Injection"],
    "xxe": ["XML External Entities (XXE)"],
    "csrf": ["Cross-Site Request Forgery (CSRF)"],
    "open-redirect": ["Open Redirect"],
    "path-traversal": ["Path Traversal"],
    "cmd-injection": ["Command Injection - Generic", "OS Command Injection"],
    "auth-bypass": [
        "Authentication Bypass Using an Alternate Path or Channel",
        "Improper Authentication - Generic",
    ],
    "info-disclosure": [
        "Information Disclosure",
        "Information Exposure Through an Error Message",
    ],
    "privesc": ["Privilege Escalation"],
    "race-condition": ["Race Condition", "Time-of-check Time-of-use (TOCTOU) Race Condition"],
    "subdomain-takeover": ["Subdomain Takeover"],
    "business-logic": ["Business Logic Errors"],
    "broken-access": ["Violation of Secure Design Principles", "Improper Access Control - Generic"],
}

# CWE numbers (probed at runtime; cwe:<number> is currently NOT supported
# by the API → automatic fallback to weakness-name queries)
CWE_IDS: dict[str, list[int]] = {
    "xss": [79],
    "sqli": [89],
    "ssrf": [918],
    "idor": [639],
    "rce": [78, 94],
    "xxe": [611],
    "csrf": [352],
    "open-redirect": [601],
    "path-traversal": [22, 23, 35, 36],
    "cmd-injection": [78],
    "auth-bypass": [287, 288, 290, 303],
    "info-disclosure": [200, 209, 532],
    "privesc": [269],
    "race-condition": [362, 367],
    "subdomain-takeover": [],
    "business-logic": [840],
    "broken-access": [862, 863, 732],
}


def build_cwe_query(cwe_names: list[str], disclosed_only: bool = True) -> str:
    """Combined queryString (for non-API engines / dorks)."""
    quoted = [f'"{name}"' for name in cwe_names]
    if len(quoted) == 1:
        q = f"cwe:{quoted[0]}"
    else:
        q = f"cwe:({' OR '.join(quoted)})"
    if disclosed_only:
        q += " AND disclosed:true"
    return q


def build_vuln_query(vuln_name: str, disclosed_only: bool = True) -> str:
    key = vuln_name.lower().strip().replace(" ", "-")
    if key in CWE_PRESETS:
        return build_cwe_query(CWE_PRESETS[key], disclosed_only)
    q = f'cwe:"{vuln_name}"'
    if disclosed_only:
        q += " AND disclosed:true"
    return q


# ─────────────────────────────────────────────────────────────
# Incremental checkpoint (resume after Ctrl+C / crash)
# ─────────────────────────────────────────────────────────────
class Checkpoint:
    """One JSON line per fetched page + per-query 'done' markers."""

    def __init__(self, output_file: str):
        base, _ = os.path.splitext(output_file)
        self.path = base + ".partial.jsonl"

    def load(self):
        """→ (items_by_query, state); state = {query: {label, last_page, done}}"""
        items_by_query, state = {}, {}
        if not os.path.exists(self.path):
            return items_by_query, state
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue   # truncated line (crash) → skip it
                    q = rec.get("query", "")
                    if rec.get("type") == "done":
                        if q in state:
                            state[q]["done"] = True
                    elif rec.get("type") == "page":
                        st = state.setdefault(q, {"label": rec.get("label", ""),
                                                  "last_page": 0, "done": False})
                        try:
                            p = int(rec.get("page", 0) or 0)
                        except (TypeError, ValueError):
                            p = 0
                        st["last_page"] = max(st["last_page"], p)
                        bucket = items_by_query.setdefault(q, {})
                        for it in rec.get("items") or []:
                            if it.get("id"):
                                bucket[it["id"]] = it
        except OSError as e:
            print(f"[!] Unreadable checkpoint ({e}) → starting fresh")
            return {}, {}
        return items_by_query, state

    def append_page(self, query, label, page, items):
        rec = {"type": "page", "query": query, "label": label,
               "page": page, "items": items}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def mark_done(self, query):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"type": "done", "query": query}) + "\n")

    def clear(self):
        if os.path.exists(self.path):
            os.remove(self.path)


# ─────────────────────────────────────────────────────────────
# Engine 1: official HackerOne REST API
# ─────────────────────────────────────────────────────────────
class HackerOneAPISearcher:
    BASE_URL = "https://api.hackerone.com/v1/hackers/hacktivity"
    API_ROOT = "https://api.hackerone.com"
    MAX_PAGE_SIZE = 50   # observed server cap; asking for more shrinks the window

    def __init__(self, username: str, token: str, page_size: int = 50):
        self.session = requests.Session()
        self.session.auth = (username, token)
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "H1DorkCollector/2.3 (research tool)",
        })
        if page_size > self.MAX_PAGE_SIZE:
            print(f"  [i] page[size] capped to {self.MAX_PAGE_SIZE} "
                  f"(requested {page_size}):")
            print("      requesting MORE shrinks the reachable pagination "
                  "window (observed).")
        self.page_size = max(1, min(page_size, self.MAX_PAGE_SIZE))
        self.effective_page_size = None
        self._test_auth()

    def _test_auth(self):
        try:
            resp = self.session.get(
                self.BASE_URL,
                params={"page[size]": 1, "queryString": "disclosed:true"},
                timeout=15,
            )
            if resp.status_code in (401, 403):
                print("[!] Authentication failed. Check H1_USERNAME and H1_TOKEN.")
                print("    → https://hackerone.com/settings/api_token/edit")
                sys.exit(1)
            resp.raise_for_status()
            print("[✓] HackerOne authentication OK")
        except requests.RequestException as e:
            print(f"[!] Could not reach the HackerOne API: {e}")
            sys.exit(1)

    # ── transport ───────────────────────────────────────────
    def _request(self, params=None, url=None, max_attempts=6):
        """Robust GET. Returns (json, None) or (None, error_message)."""
        for attempt in range(max_attempts):
            try:
                resp = self.session.get(url or self.BASE_URL, params=params, timeout=30)
            except requests.RequestException as e:
                wait = min(2 ** attempt, 30)
                print(f"  [!] Network error: {e} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 429:
                wait = self._retry_after(resp)
                print(f"  [!] Rate limited (429) — waiting {wait}s")
                time.sleep(wait)
                continue
            if 500 <= resp.status_code < 600:
                wait = min(2 ** attempt, 30)
                print(f"  [!] Server error {resp.status_code} — retrying in {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code in (400, 422):
                return None, f"query rejected ({resp.status_code}): {resp.text[:200]}"
            try:
                resp.raise_for_status()
                return resp.json(), None
            except ValueError:
                return None, "non-JSON response"
        return None, "too many consecutive errors"

    @staticmethod
    def _retry_after(resp) -> int:
        ra = resp.headers.get("Retry-After", "60")
        try:
            return min(max(int(ra), 1), 300)
        except (TypeError, ValueError):
            return 60   # Retry-After in HTTP-date format → safe default

    # ── parsing ─────────────────────────────────────────────
    def _parse_item(self, item: dict) -> dict | None:
        attrs = item.get("attributes", {}) or {}
        rels = item.get("relationships", {}) or {}

        report_id = item.get("id", "")
        title = (attrs.get("title") or "").strip()
        url = attrs.get("url") or f"https://hackerone.com/reports/{report_id}"
        severity = attrs.get("severity_rating") or "N/A"
        bounty = attrs.get("total_awarded_amount") or 0
        votes = attrs.get("votes", 0)
        cwe = attrs.get("cwe") or ""
        cve_ids = attrs.get("cve_ids") or ""
        disclosed_at = attrs.get("disclosed_at") or ""
        submitted_at = attrs.get("submitted_at") or ""
        substate = attrs.get("substate") or ""
        latest_activity = attrs.get("latest_disclosable_activity_at") or ""

        program_data = (rels.get("program") or {}).get("data") or {}
        program_attrs = program_data.get("attributes") or {}
        program_name = program_attrs.get("name", "N/A")
        program_handle = program_attrs.get("handle", "")

        reporter_data = (rels.get("reporter") or {}).get("data") or {}
        reporter_attrs = reporter_data.get("attributes") or {}
        reporter_name = reporter_attrs.get("username", "N/A")

        return {
            "id": report_id,
            "title": title,
            "link": url,
            "severity": severity,
            "bounty": bounty,
            "votes": votes,
            "cwe": cwe,
            "cve_ids": cve_ids if isinstance(cve_ids, str) else "|".join(cve_ids),
            "program": program_name,
            "program_handle": program_handle,
            "reporter": reporter_name,
            "disclosed_at": disclosed_at,
            "submitted_at": submitted_at,
            "latest_activity": latest_activity,
            "substate": substate,
            "snippet": (
                f"Program: {program_name} | Severity: {severity} | "
                f"Bounty: ${bounty} | Reporter: {reporter_name}"
            ),
        }

    @staticmethod
    def _sort_key(it):
        return it.get("latest_activity") or it.get("disclosed_at") or \
               it.get("submitted_at") or ""

    # ── single-direction pagination ─────────────────────────
    def _fetch_pass(self, query_string, sort, max_items, label, delay, quiet=False,
                    start_page=1, on_page=None):
        """
        Paginate in ONE direction (resumable from start_page).

        Natural end = partial page followed by an empty page (or empty page 1).
        Capped      = full page followed by an empty page (exact-multiple end OR
                      deep-pagination wall — pass 2 will tell them apart).
        """
        results = []
        page = start_page
        next_url = None
        exhausted = False
        capped = False
        last_n = 0

        while len(results) < max_items:
            if next_url:
                data, err = self._request(url=next_url)
            else:
                data, err = self._request(params={
                    "queryString": query_string,
                    "page[number]": page,
                    "page[size]": self.page_size,
                    "sort": sort,
                })

            if err:
                print(f"  [{label}] [!] {err}")
                break

            if not isinstance(data, dict):
                data = {}
            items = data.get("data") or []

            if not items:
                full_ref = self.effective_page_size or self.page_size
                if page == 1:
                    exhausted = True        # zero results
                elif last_n == full_ref and last_n > 0:
                    capped = True           # full page → empty page: ambiguous
                else:
                    exhausted = True        # partial page → empty page: natural end
                break

            page_items = []
            for item in items:
                parsed = self._parse_item(item)
                if parsed:
                    results.append(parsed)
                    page_items.append(parsed)

            if on_page:
                try:
                    on_page(page, page_items)
                except OSError as e:
                    print(f"  [{label}] [!] checkpoint write failed: {e}")

            n = len(items)

            # Learn the server's real per-page cap only from EVIDENCE.
            # A partial first page can just be a small result set, not a cap.
            if self.effective_page_size is None:
                if n >= self.page_size:
                    self.effective_page_size = n
                elif last_n and n > 0:
                    # partial page followed by a NON-empty page → real server cap
                    self.effective_page_size = max(last_n, n)
                    if not quiet:
                        print(f"  [i] API serves {self.effective_page_size} items/page "
                              f"(requested {self.page_size})")
            elif n > self.effective_page_size:
                self.effective_page_size = n

            last_n = n

            if not quiet:
                print(f"  [{label}] [+] Page {page} — {n} items — Total: {len(results)}")

            links = data.get("links")
            next_url = links.get("next") if isinstance(links, dict) else None
            if next_url and next_url.startswith("/"):
                next_url = self.API_ROOT + next_url

            page += 1
            time.sleep(delay)

        hit_max = (not exhausted) and (not capped) and len(results) >= max_items
        return {"items": results, "exhausted": exhausted,
                "capped": capped, "hit_max": hit_max}

    @staticmethod
    def _report_pass(title, p):
        n = len(p["items"])
        if p["capped"]:
            print(f"  [{title}] {n} items — deep pagination cap reached "
                  f"(API returns data:[] beyond)")
        elif p["exhausted"]:
            print(f"  [{title}] {n} items — natural end of results")
        elif p["hit_max"]:
            print(f"  [{title}] {n} items — --max budget reached")
        else:
            print(f"  [{title}] {n} items")

    @staticmethod
    def _finalize(results, max_results):
        def key(it):
            return it.get("latest_activity") or it.get("disclosed_at") or ""
        results.sort(key=key, reverse=True)
        return results[:max_results]

    # ── cwe:<number> probe ──────────────────────────────────
    def cwe_id_works(self, cwe_id, disclosed_only=True):
        q = f"cwe:{cwe_id}"
        if disclosed_only:
            q += " AND disclosed:true"
        data, err = self._request(params={
            "queryString": q, "page[number]": 1, "page[size]": 1,
            "sort": "-latest_disclosable_activity_at",
        })
        return (not err) and isinstance(data, dict) and bool(data.get("data"))

    # ── date-filter probe (rare fallback) ────────────────────
    @staticmethod
    def _date_frag(field, syntax, lo, hi):
        if syntax == "dotdot":
            return f"{field}:{lo.isoformat()}..{hi.isoformat()}"
        return f"{field}:[{lo.isoformat()} TO {hi.isoformat()}]"

    def _probe_date_filter(self, base_query):
        today = date.today()
        lo_new = date(today.year - 3, 1, 1)
        hi_new = date(today.year + 1, 1, 1)
        for field in ("disclosed_at", "submitted_at"):
            for syntax in ("dotdot", "lucene"):
                frag_old = self._date_frag(field, syntax, date(2001, 1, 1), date(2002, 12, 31))
                data, err = self._request(params={
                    "queryString": f"{base_query} AND {frag_old}",
                    "page[number]": 1, "page[size]": 5,
                    "sort": "-latest_disclosable_activity_at",
                })
                if err or not isinstance(data, dict) or (data.get("data") or []):
                    continue
                frag_new = self._date_frag(field, syntax, lo_new, hi_new)
                data2, err2 = self._request(params={
                    "queryString": f"{base_query} AND {frag_new}",
                    "page[number]": 1, "page[size]": 5,
                    "sort": "-latest_disclosable_activity_at",
                })
                if err2 or not isinstance(data2, dict) or not (data2.get("data") or []):
                    continue
                print(f"  [i] Date filters supported ({field}, syntax '{syntax}')")
                return field, syntax
        return None

    def _walk_windows(self, query_string, field, syntax, lo, hi, sort_field,
                      seen, all_results, max_results, delay):
        stack = [(lo, hi)]
        while stack:
            wlo, whi = stack.pop()
            frag = self._date_frag(field, syntax, wlo, whi)
            q = f"{query_string} AND {frag}"
            p = self._fetch_pass(q, f"-{sort_field}", max_results, "◫", delay, quiet=True)
            added = 0
            for it in p["items"]:
                if it["id"] not in seen:
                    seen.add(it["id"])
                    all_results.append(it)
                    added += 1
            print(f"      ⊞ Window {wlo} → {whi}: {len(p['items'])} items, "
                  f"{added} new")
            if p["hit_max"] or p["exhausted"]:
                continue
            if (whi - wlo).days <= 31:
                print(f"      [!] {wlo} → {whi} still exceeds the cap — window abandoned")
                continue
            mid = wlo + (whi - wlo) / 2
            stack.append((wlo, mid))
            stack.append((mid, whi))

    def _fill_middle_gap(self, query_string, sort_field, seen, all_results,
                         max_results, delay):
        print("  [⋯] Attempting to fill the gap with date windows…")
        probe = self._probe_date_filter(query_string)
        if probe is None:
            print("  [!] Date filters not supported by this endpoint →")
            print("      the middle slice cannot be retrieved with this query.")
            print("      Tip: split the query (per-name mode already does this).")
            return
        field, syntax = probe
        lo = date(2010, 1, 1)
        hi = date.today() + timedelta(days=1)
        self._walk_windows(query_string, field, syntax, lo, hi, sort_field,
                           seen, all_results, max_results, delay)
        print(f"  [✓] Gap filling done — {len(all_results)} unique total")

    # ── main search ─────────────────────────────────────────
    def search(self, query_string, max_results=5000, page_size=None,
               sort="-latest_disclosable_activity_at", delay=0.6,
               start_page=1, on_page=None, restored_items=None):
        if page_size:
            self.page_size = max(1, min(page_size, self.MAX_PAGE_SIZE))

        sort_field = sort.lstrip("-")
        sort_desc = f"-{sort_field}"
        sort_asc = sort_field

        seen = set()
        all_results = []
        if restored_items:
            for it in restored_items:
                if it.get("id") and it["id"] not in seen:
                    seen.add(it["id"])
                    all_results.append(it)

        print("\n  [▼] Pass 1 — descending sort (newest → oldest)")
        p1 = self._fetch_pass(query_string, sort_desc, max_results, "▼", delay,
                              start_page=start_page, on_page=on_page)
        for it in p1["items"]:
            if it["id"] not in seen:
                seen.add(it["id"])
                all_results.append(it)
        self._report_pass("▼ Pass 1", p1)

        if p1["hit_max"]:
            print("  [i] --max budget reached in pass 1 (intentional truncation)")
            return self._finalize(all_results, max_results)

        if p1["exhausted"]:
            print("  [✓] Natural end of results reached → COMPLETE set retrieved")
            return self._finalize(all_results, max_results)

        # pass 2 (rare: only when pass 1 hits the pagination wall)
        print("\n  [▲] Pass 2 — ascending sort (oldest → newest)")
        print("      if both passes overlap, the set is complete by construction")
        time.sleep(delay * 2)
        budget = max(max_results - len(all_results), 0) + 500
        p2 = self._fetch_pass(query_string, sort_asc, budget, "▲", delay)

        new2 = 0
        for it in p2["items"]:
            if it["id"] not in seen:
                seen.add(it["id"])
                all_results.append(it)
                new2 += 1
        self._report_pass("▲ Pass 2", p2)

        # SANITY CHECK: is the ascending sort actually applied?
        # (v2.0 lesson: without this, an overlap proves nothing)
        asc_ok = True
        if (sort_field == "latest_disclosable_activity_at"
                and p1["items"] and p2["items"]):
            d_desc = self._sort_key(p1["items"][0])
            d_asc = self._sort_key(p2["items"][0])
            if d_desc and d_asc and d_asc >= d_desc:
                asc_ok = False
                print("  [!] Ascending sort appears to be IGNORED by the API "
                      "(pass 2 ≈ same end as pass 1)")
                print("      → overlap does NOT prove completeness")

        overlap = len(p2["items"]) - new2
        if overlap > 0 and asc_ok:
            print(f"  [✓] Overlap of {overlap} items → complete collection "
                  f"({len(all_results)} unique)")
        elif p2["items"]:
            if overlap > 0:
                print("  [!] Overlap without a reliable ascending sort → "
                      "completeness unproven")
            else:
                print("  [!] No overlap → a middle slice is missing")
            self._fill_middle_gap(query_string, sort_field, seen, all_results,
                                  max_results, delay)
        else:
            print("  [!] Pass 2 empty (unexpected API behavior)")

        return self._finalize(all_results, max_results)


# ─────────────────────────────────────────────────────────────
# Engines 2/3/4
# ─────────────────────────────────────────────────────────────
class GoogleCSESearcher:
    BASE_URL = "https://www.googleapis.com/customsearch/v1"

    def __init__(self, api_key: str, cse_id: str):
        self.api_key = api_key
        self.cse_id = cse_id
        self.session = requests.Session()

    def search(self, query: str, max_results: int = 100, **_kw) -> list[dict]:
        results = []
        start = 1
        while len(results) < max_results and start <= 91:
            params = {"key": self.api_key, "cx": self.cse_id, "q": query,
                      "start": start, "num": min(10, max_results - len(results))}
            try:
                resp = self.session.get(self.BASE_URL, params=params, timeout=30)
                if resp.status_code == 429:
                    print("  [!] Rate limited — waiting 60s...")
                    time.sleep(60)
                    continue
                if resp.status_code == 403:
                    err = resp.json().get("error", {}).get("message", "")
                    print(f"  [!] Google CSE quota/error: {err}")
                    break
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                print(f"  [!] Network error: {e}")
                break
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                link = item.get("link", "")
                if "/reports/" in link and "hackerone.com" in link:
                    results.append({"title": item.get("title", "").strip(),
                                    "link": link,
                                    "snippet": item.get("snippet", "").strip()})
            total = int(data.get("searchInformation", {}).get("totalResults", 0))
            print(f"  [+] Page {start // 10 + 1} — {len(results)} reports "
                  f"(≈{total} total)")
            start += 10
            time.sleep(1.5)
        return results[:max_results]


class SerpAPISearcher:
    BASE_URL = "https://serpapi.com/search.json"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()

    def search(self, query: str, max_results: int = 100, **_kw) -> list[dict]:
        results = []
        start = 0
        while len(results) < max_results:
            params = {"api_key": self.api_key, "engine": "google",
                      "q": query, "start": start, "num": 10}
            try:
                resp = self.session.get(self.BASE_URL, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                print(f"  [!] SerpAPI error: {e}")
                break
            if "error" in data:
                print(f"  [!] SerpAPI: {data['error']}")
                break
            organic = data.get("organic_results", [])
            if not organic:
                break
            for item in organic:
                link = item.get("link", "")
                if "/reports/" in link and "hackerone.com" in link:
                    results.append({"title": item.get("title", "").strip(),
                                    "link": link,
                                    "snippet": item.get("snippet", "").strip()})
            print(f"  [+] Page {start // 10 + 1} — {len(results)} reports")
            if not data.get("serpapi_pagination", {}).get("next"):
                break
            start += 10
            time.sleep(1)
        return results[:max_results]


class HackerOneGQLSearcher:
    GRAPHQL_URL = "https://hackerone.com/graphql"

    QUERY = """
    query HacktivityQuery($queryString: String!, $cursor: String, $count: Int!) {
      hacktivity_items(
        first: $count
        after: $cursor
        query: $queryString
        order_by: {field: popular, direction: DESC}
      ) {
        total_count
        edges {
          node {
            ... on HacktivityItemInterface {
              id
              votes { total_count }
              reporter { username }
            }
            ... on Disclosed {
              report { title url substate created_at severity_rating }
              team { name handle }
            }
            ... on HacktivityItemHackerPublished {
              report { title url substate created_at severity_rating }
              team { name handle }
            }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),
        })

    def search(self, query_string: str, max_results: int = 500, **_kw) -> list[dict]:
        results = []
        cursor = None
        while len(results) < max_results:
            batch = min(25, max_results - len(results))
            variables = {"queryString": query_string, "cursor": cursor, "count": batch}
            try:
                resp = self.session.post(
                    self.GRAPHQL_URL,
                    json={"query": self.QUERY, "variables": variables},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                print(f"  [!] GraphQL error: {e}")
                break
            if "errors" in data:
                print(f"  [!] GraphQL errors: {data['errors'][0].get('message', '')}")
                break
            hacktivity = data.get("data", {}).get("hacktivity_items")
            if not hacktivity:
                break
            edges = hacktivity.get("edges", [])
            if not edges:
                break
            for edge in edges:
                node = edge.get("node", {})
                report = node.get("report")
                team = node.get("team")
                if not report or not report.get("url"):
                    continue
                results.append({
                    "title": report.get("title", "").strip(),
                    "link": report["url"],
                    "severity": report.get("severity_rating") or "N/A",
                    "program": team.get("name", "N/A") if team else "N/A",
                    "reporter": (node.get("reporter") or {}).get("username", "N/A"),
                    "snippet": (f"Program: {team.get('name', 'N/A') if team else 'N/A'} | "
                                f"Severity: {report.get('severity_rating', 'N/A')}"),
                })
            page_info = hacktivity.get("pageInfo", {})
            total = hacktivity.get("total_count", "?")
            print(f"  [+] {len(results)}/{total} reports collected")
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            time.sleep(0.8)
        return results[:max_results]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def build_google_dork(vuln_name: str, extra: str = "") -> str:
    dork = f'site:hackerone.com "{vuln_name}" inurl:report'
    if extra:
        dork += f" {extra}"
    return dork


def deduplicate(results: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for r in results:
        url = r["link"].rstrip("/")
        if url not in seen:
            seen.add(url)
            unique.append(r)
    return unique


def save_results(results: list[dict], output_file: str,
                 links_only: bool = False, fmt: str = "txt", note: str = ""):
    if fmt == "json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif fmt == "jsonl":
        with open(output_file, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    elif fmt == "csv":
        import csv
        fields = ["title", "link", "severity", "program", "reporter",
                  "bounty", "cwe", "disclosed_at"]
        if results:
            fields = [f for f in fields if f in results[0]]
        with open(output_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
    else:  # txt
        with open(output_file, "w", encoding="utf-8") as f:
            if links_only:
                for r in results:
                    f.write(r["link"] + "\n")
            else:
                f.write(f"# H1DorkCollector v2.3 — "
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
                f.write(f"# {len(results)} reports collected\n")
                if note:
                    f.write(f"# {note}\n")
                f.write("=" * 80 + "\n\n")
                for i, r in enumerate(results, 1):
                    f.write(f"[{i}] {r['title']}\n")
                    f.write(f"    URL:      {r['link']}\n")
                    sev = r.get("severity", "")
                    if sev and sev != "N/A":
                        f.write(f"    Severity: {sev}\n")
                    prog = r.get("program", "")
                    if prog and prog != "N/A":
                        f.write(f"    Program:  {prog}\n")
                    rep = r.get("reporter", "")
                    if rep and rep != "N/A":
                        f.write(f"    Reporter: {rep}\n")
                    bounty = r.get("bounty")
                    if bounty:
                        f.write(f"    Bounty:   ${bounty}\n")
                    f.write("\n")

    if not links_only:
        base, _ = os.path.splitext(output_file)
        links_file = f"{base}_links.txt"
        with open(links_file, "w", encoding="utf-8") as f:
            for r in results:
                f.write(r["link"] + "\n")
        print(f"\n{'═' * 55}")
        print(f"  ✓  {len(results)} reports saved → {output_file}")
        print(f"  ✓  {len(results)} links          → {links_file}")
        print(f"{'═' * 55}")
    else:
        print(f"\n{'═' * 55}")
        print(f"  ✓  {len(results)} links saved → {output_file}")
        print(f"{'═' * 55}")


def list_presets():
    print("\n  Available CWE presets:")
    print("  " + "─" * 60)
    for key in sorted(CWE_PRESETS):
        ids = CWE_IDS.get(key, [])
        id_str = ("cwe:" + ",".join(map(str, ids))) if ids else "names only"
        names = ", ".join(CWE_PRESETS[key])
        if len(names) > 40:
            names = names[:37] + "..."
        print(f"  {key:<20} {id_str:<18} {names}")
    print()


# ─────────────────────────────────────────────────────────────
# Query building
# ─────────────────────────────────────────────────────────────
def build_api_queries(args, searcher, disclosed_only):
    def q_id(i):
        return f"cwe:{i}" + (" AND disclosed:true" if disclosed_only else "")

    def q_name(n):
        return f'cwe:"{n}"' + (" AND disclosed:true" if disclosed_only else "")

    queries = []

    def add_preset(key):
        names = CWE_PRESETS[key]
        ids = CWE_IDS.get(key, [])
        add_names = True
        if ids and args.query_mode in ("auto", "ids"):
            print(f"[*] Probing cwe:<number> for '{key}'…")
            usable = [i for i in ids if searcher.cwe_id_works(i, disclosed_only)]
            if usable:
                idlist = ", ".join(f"cwe:{i}" for i in usable)
                print(f"    ✓ works: {idlist}")
                for i in usable:
                    queries.append((f"{key} ‹cwe:{i}›", q_id(i)))
                add_names = (args.query_mode == "auto")
            else:
                print("    ✗ not supported → weakness-name queries")
        if add_names:
            for n in names:
                queries.append((f"{key} ‹{n}›", q_name(n)))

    if args.query:
        queries.append(("custom", args.query))
    elif args.cwe_id:
        queries.append((f"cwe:{args.cwe_id}", q_id(args.cwe_id)))
    elif args.cwe_preset:
        key = args.cwe_preset.lower().strip()
        if key not in CWE_PRESETS:
            print(f"[!] Unknown preset: '{key}'")
            list_presets()
            sys.exit(1)
        add_preset(key)
    elif args.vuln:
        k = args.vuln.lower().strip().replace(" ", "-")
        if k in CWE_PRESETS:
            add_preset(k)
        else:
            queries.append((args.vuln, q_name(args.vuln)))
    elif args.vuln_list:
        with open(args.vuln_list, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    k = line.lower().strip().replace(" ", "-")
                    if k in CWE_PRESETS:
                        add_preset(k)
                    else:
                        queries.append((line, q_name(line)))
    return queries


def build_simple_queries(args, disclosed_only):
    queries = []
    if args.query:
        queries.append(("custom", args.query))
    elif args.cwe_id:
        q = f"cwe:{args.cwe_id}" + (" AND disclosed:true" if disclosed_only else "")
        queries.append((f"cwe:{args.cwe_id}", q))
    elif args.cwe_preset:
        key = args.cwe_preset.lower().strip()
        if key not in CWE_PRESETS:
            print(f"[!] Unknown preset: '{key}'")
            list_presets()
            sys.exit(1)
        queries.append((key, build_cwe_query(CWE_PRESETS[key], disclosed_only)))
    elif args.vuln:
        queries.append((args.vuln, build_vuln_query(args.vuln, disclosed_only)))
    elif args.vuln_list:
        with open(args.vuln_list, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    queries.append((line, build_vuln_query(line, disclosed_only)))
    return queries


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
def main():
    banner = r"""
    ╔═══════════════════════════════════════════════════════╗
    ║       H1DorkCollector  v2.3                           ║
    ║  Automated HackerOne Report Link Collector            ║
    ║  github.com • hackerone.com/hacktivity                ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="Automated HackerOne report link collection by "
                    "vulnerability class",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --cwe-preset xss --engine hackerone-api
  %(prog)s --cwe-preset ssrf --engine hackerone-api -o ssrf.txt
  %(prog)s -v "SSRF" --engine hackerone-api
  %(prog)s --query 'cwe:"SSRF" AND disclosed:true' --engine hackerone-api
  %(prog)s --cwe-preset xss --engine hackerone-api --format csv
  %(prog)s --list-presets

Interrupted? Re-run the SAME command: the collection resumes
(checkpoint <output>.partial.jsonl, deleted when finished).
        """,
    )

    src = parser.add_mutually_exclusive_group()
    src.add_argument("-v", "--vuln", help="vulnerability name (e.g. 'SSRF', 'XSS')")
    src.add_argument("--vuln-list", help="file with vulnerability names (one per line)")
    src.add_argument("--cwe-preset", help="CWE preset (e.g. xss, ssrf, sqli)")
    src.add_argument("--cwe-id", type=int, help="CWE number (e.g. 79 = XSS)")
    src.add_argument("--query", help="raw Lucene queryString (Hacktivity format)")

    parser.add_argument("--engine",
                        choices=["hackerone-api", "hackerone-gql", "google-cse",
                                 "serpapi"],
                        default="hackerone-api", help="engine (default: hackerone-api)")
    parser.add_argument("--query-mode", choices=["auto", "ids", "names"],
                        default="auto",
                        help="hackerone-api strategy: auto = cwe:<number> if "
                             "supported + names")
    parser.add_argument("-o", "--output", help="output file (auto-generated if omitted)")
    parser.add_argument("--max", type=int, default=5000,
                        help="max results per query (default 5000)")
    parser.add_argument("--page-size", type=int, default=50,
                        help="items/page, 1-50 (default 50; asking for more "
                             "shrinks the reachable window)")
    parser.add_argument("--links-only", action="store_true",
                        help="save only the links")
    parser.add_argument("--format", choices=["txt", "json", "jsonl", "csv"],
                        default="txt", help="output format (default: txt)")
    parser.add_argument("--sort", default="-latest_disclosable_activity_at",
                        help="sort (default: -latest_disclosable_activity_at)")
    parser.add_argument("--include-undisclosed", action="store_true",
                        help="drop the disclosed:true filter")
    parser.add_argument("--delay", type=float, default=0.6,
                        help="delay between requests in seconds")
    parser.add_argument("--extra", default="", help="extra Google dork filters")
    parser.add_argument("--list-presets", action="store_true",
                        help="list the CWE presets")

    args = parser.parse_args()

    if args.list_presets:
        list_presets()
        sys.exit(0)

    if not any([args.vuln, args.vuln_list, args.cwe_preset, args.query, args.cwe_id]):
        parser.error("specify a source: -v, --vuln-list, --cwe-preset, "
                     "--cwe-id or --query")

    disclosed_only = not args.include_undisclosed

    # ── engine init ──
    searcher = None
    if args.engine == "hackerone-api":
        username = os.environ.get("H1_USERNAME")
        token = os.environ.get("H1_TOKEN")
        if not username or not token:
            print("[!] Missing environment variables: H1_USERNAME and H1_TOKEN")
            print()
            print("    Setup (free, 2 minutes):")
            print("    1. Go to https://hackerone.com/settings/api_token/edit")
            print("    2. Create an API token")
            print()
            print('    export H1_USERNAME="your_h1_username"')
            print('    export H1_TOKEN="your_api_token"')
            sys.exit(1)
        searcher = HackerOneAPISearcher(username, token, page_size=args.page_size)
    elif args.engine == "hackerone-gql":
        searcher = HackerOneGQLSearcher()
    elif args.engine == "google-cse":
        api_key = os.environ.get("GOOGLE_API_KEY")
        cse_id = os.environ.get("GOOGLE_CSE_ID")
        if not api_key or not cse_id:
            print("[!] Missing environment variables: GOOGLE_API_KEY and GOOGLE_CSE_ID")
            print("    1. https://console.cloud.google.com/apis/library/"
                  "customsearch.googleapis.com")
            print("    2. https://console.cloud.google.com/apis/credentials")
            print("    3. https://programmablesearchengine.google.com/")
            sys.exit(1)
        searcher = GoogleCSESearcher(api_key, cse_id)
    elif args.engine == "serpapi":
        api_key = os.environ.get("SERPAPI_KEY")
        if not api_key:
            print("[!] Missing environment variable: SERPAPI_KEY")
            print("    → https://serpapi.com/")
            sys.exit(1)
        searcher = SerpAPISearcher(api_key)

    # ── build queries ──
    if args.engine == "hackerone-api":
        queries = build_api_queries(args, searcher, disclosed_only)
    else:
        queries = build_simple_queries(args, disclosed_only)

    if not queries:
        print("[!] No queries built.")
        sys.exit(1)

    # ── dedup queries (the cwe: filter is case-insensitive:
    #    "Cross-Site Scripting (XSS)" ≡ "Cross-site Scripting (XSS)") ──
    seen_q: dict[str, str] = {}
    deduped = []
    for label, q in queries:
        key = " ".join(q.lower().split())
        if key in seen_q:
            print(f"[i] Duplicate query skipped: '{label}' (≡ '{seen_q[key]}')")
            continue
        seen_q[key] = label
        deduped.append((label, q))
    queries = deduped

    # ── output filename ──
    if not args.output:
        if args.cwe_preset:
            base = args.cwe_preset
        elif args.cwe_id:
            base = f"cwe{args.cwe_id}"
        elif args.vuln:
            base = args.vuln
        elif args.query:
            base = "custom"
        else:
            base = "vulns"
        base = "".join(c if c.isalnum() else "_"
                       for c in base.lower()).strip("_") or "results"
        ext = args.format
        if args.links_only and ext == "txt":
            args.output = f"h1_{base}_links.txt"
        else:
            args.output = f"h1_{base}.{ext}"

    print(f"[*] Engine     : {args.engine}")
    print(f"[*] Queries    : {len(queries)}")
    for label, q in queries:
        shown = q[:70] + ("…" if len(q) > 70 else "")
        print(f"               → {label}: {shown}")
    print(f"[*] Max/query  : {args.max}")
    print(f"[*] Output     : {args.output} ({args.format})")

    # ── checkpoint / resume ──
    ckpt = Checkpoint(args.output)
    items_by_query, state = ckpt.load()
    if state:
        cached = sum(len(v) for v in items_by_query.values())
        done = sum(1 for s in state.values() if s.get("done"))
        print(f"[*] Resume: {done} query(ies) already completed, "
              f"{cached} items cached ({ckpt.path})")

    all_results = []
    interrupted = False

    try:
        for label, query_string in queries:
            print(f"\n{'─' * 55}")
            print(f"[*] {label}")
            print(f"    Query: {query_string[:80]}"
                  f"{'...' if len(query_string) > 80 else ''}")
            print(f"{'─' * 55}")

            if args.engine in ("google-cse", "serpapi"):
                dork = build_google_dork(label, args.extra)
                print(f"    Dork: {dork}")
                results = searcher.search(dork, args.max)
                print(f"  [=] {len(results)} reports for '{label}'")
                all_results.extend(results)
                continue

            if args.engine == "hackerone-gql":
                results = searcher.search(query_string, max_results=args.max)
                print(f"  [=] {len(results)} reports for '{label}'")
                all_results.extend(results)
                continue

            # ── hackerone-api: skip if done, resume otherwise ──
            st = state.get(query_string, {})
            restored = list(items_by_query.get(query_string, {}).values())

            if st.get("done"):
                print(f"  [✓] Already collected (checkpoint) — "
                      f"{len(restored)} items, query skipped")
                all_results.extend(restored)
                continue

            start_page = 1
            if st.get("last_page"):
                start_page = max(1, st["last_page"] - 1)   # anti-drift cushion
                print(f"  [i] Resuming pagination at page {start_page} "
                      f"({len(restored)} items already cached)")

            def on_page(page, items, _q=query_string, _l=label):
                ckpt.append_page(_q, _l, page, items)

            results = searcher.search(
                query_string,
                max_results=args.max,
                page_size=args.page_size,
                sort=args.sort,
                delay=args.delay,
                start_page=start_page,
                on_page=on_page,
                restored_items=restored,
            )
            ckpt.mark_done(query_string)
            print(f"  [=] {len(results)} reports for '{label}'")
            all_results.extend(results)

    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] Ctrl+C — stopping. Saving the results collected so far…")

    unique = deduplicate(all_results)
    removed = len(all_results) - len(unique)
    if removed:
        print(f"\n[i] {removed} duplicates removed")

    if unique:
        note = ""
        if interrupted:
            note = ("PARTIAL — interrupted (Ctrl+C). "
                    "Re-run the same command to resume.")
        save_results(unique, args.output, args.links_only, args.format, note)
        if interrupted:
            print("[i] Checkpoint kept → re-run the same command to continue.")
        else:
            ckpt.clear()
            print("[✓] Collection complete — checkpoint removed.")
    else:
        print("\n[!] No results found.")
        sys.exit(1)


if __name__ == "__main__":
    main()
