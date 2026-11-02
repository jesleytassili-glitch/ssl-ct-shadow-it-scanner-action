#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSL/TLS CT Log, SPF/DMARC & Shadow-IT Attack Surface Scanner — GitHub Action Runner (ssl-ct-shadow-it-scanner-action)
Pure Python 3.11+ standard library (<3s cold start).
Supports RapidAPI (@b2bquantapis), Apify Store (@b2b-quant-apis), and Zero-Key Instant Preview.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APIFY_OWNER = "b2b-quant-apis"
DEFAULT_MODE = "ct-subdomains"
DEFAULT_TARGETS = "github.com,cloudflare.com"
MODES: dict[str, dict[str, str]] = {
    "ct-subdomains": {
        "slug": "b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor",
        "title": "SSL/TLS Certificate Transparency & Shadow-IT Subdomain Audit",
        "payload_key": "domains"
    },
    "email-dns-security": {
        "slug": "global-b2b-email-domain-security-auditor",
        "title": "SPF, DMARC, BIMI & MX Anti-Spoofing Security Audit",
        "payload_key": "domains"
    },
    "rdap-whois-recon": {
        "slug": "icann-rdap-domain-whois-brand-recon",
        "title": "ICANN RDAP Domain Registration & Brand Impersonation Recon",
        "payload_key": "domains"
    }
}

VAT_REGEX = re.compile(r"^[A-Z]{2}[A-Z0-9]{6,14}$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def parse_bool(raw: str | None, default: bool = False) -> bool:
    if raw is None:
        return default
    v = str(raw).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def parse_max_results(raw: str | None, default: int = 10) -> int:
    try:
        return max(1, min(100, int(float(str(raw or default).strip()))))
    except Exception:
        return default


def parse_targets(raw: str | None) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        text = DEFAULT_TARGETS
    p = Path(text)
    if len(text) < 240 and p.is_file():
        try:
            content = p.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("["):
                arr = json.loads(content)
                if isinstance(arr, list):
                    return [str(x).strip() for x in arr if str(x).strip()][:100]
            text = content
        except Exception:
            pass
    items = [t.strip() for t in re.split(r"[,\n\r;]+", text) if t and t.strip()]
    return items[:100] or [t.strip() for t in DEFAULT_TARGETS.split(",") if t.strip()]


def build_payload(mode: str, targets: list[str], max_results: int) -> dict[str, Any]:
    meta = MODES.get(mode) or MODES[DEFAULT_MODE]
    pkey = meta["payload_key"]
    if pkey == "domains":
        cleaned = [t.lower().replace("https://", "").replace("http://", "").split("/")[0] for t in targets]
        return {pkey: cleaned, "maxResults": max_results}
    if pkey == "vatNumbers":
        cleaned = [re.sub(r"[^A-Za-z0-9]", "", t).upper() for t in targets]
        return {pkey: cleaned, "maxResults": max_results}
    if pkey == "ncmCodes":
        items = [{"ncm": re.sub(r"\D", "", t)[:8] or "84713012", "cClassTrib": "010001", "valor_item": 1000.0} for t in targets]
        return {"items": items, "maxResults": max_results}
    return {pkey: targets, "maxResults": max_results}


def http_post_json(url: str, headers: dict[str, str], payload: dict[str, Any], retries: int = 2) -> Any:
    req_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "B2BMonofocusAction/1.0 (+https://github.com/jesleytassili-glitch/ssl-ct-shadow-it-scanner-action)",
        **headers,
    }
    body = json.dumps(payload).encode("utf-8")
    ctx = ssl.create_default_context()
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url=url, data=body, headers=req_headers, method="POST")
            with urllib.request.urlopen(req, timeout=25.0, context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else []
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(0.6 * attempt)
    raise RuntimeError(f"Cloud call failed ({url}): {last_exc}")


def evaluate_risk(raw_resp: Any) -> tuple[list[dict[str, Any]], int]:
    if isinstance(raw_resp, dict):
        items = raw_resp.get("items") or raw_resp.get("data") or raw_resp.get("results")
        records = list(items) if isinstance(items, list) else [raw_resp]
    elif isinstance(raw_resp, list):
        records = [x for x in raw_resp if isinstance(x, dict)]
    else:
        records = []

    high_risk = 0
    for rec in records:
        if (
            rec.get("isSanctioned") is True
            or rec.get("matchFound") is True
            or rec.get("valid") is False
            or rec.get("expiredCertificate") is True
            or float(rec.get("riskScore") or 0) >= 75.0
        ):
            high_risk += 1
    return records, high_risk


def build_preview(mode: str, targets: list[str], max_results: int) -> tuple[list[dict[str, Any]], int]:
    meta = MODES.get(mode) or MODES[DEFAULT_MODE]
    pkey = meta["payload_key"]
    records: list[dict[str, Any]] = []
    high_risk = 0
    for raw_t in targets[:max_results]:
        flag_high = False
        syntax_ok = True
        if pkey == "vatNumbers":
            norm = re.sub(r"[^A-Za-z0-9]", "", raw_t).upper()
            syntax_ok = bool(VAT_REGEX.match(norm))
            if not syntax_ok:
                flag_high = True
        elif pkey == "domains":
            norm = raw_t.lower().replace("https://", "").replace("http://", "").split("/")[0]
            syntax_ok = bool(DOMAIN_REGEX.match(norm))
        elif pkey == "entities" and any(w in raw_t.lower() for w in ("sanctioned", "ofac-test", "blocked")):
            flag_high = True
        if flag_high:
            high_risk += 1
        records.append({
            "target": raw_t,
            "syntaxValid": syntax_ok,
            "riskLevel": "HIGH" if flag_high else "PREVIEW_ONLY",
            "summary": f"Add rapidapi_key or apify_token for live {meta['slug']} cloud verification.",
        })
    return records, high_risk


def execute_gate(env: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    cfg = env if env is not None else dict(os.environ)
    raw_mode = str(cfg.get("INPUT_MODE") or DEFAULT_MODE).strip().lower()
    mode = raw_mode if raw_mode in MODES else DEFAULT_MODE
    meta = MODES[mode]
    slug = meta["slug"]

    targets = parse_targets(cfg.get("INPUT_TARGETS"))
    max_results = parse_max_results(cfg.get("INPUT_MAX_RESULTS"), default=10)
    fail_on_high = parse_bool(cfg.get("INPUT_FAIL_ON_HIGH_RISK"), default=False)
    rapid_key = str(cfg.get("INPUT_RAPIDAPI_KEY") or "").strip()
    apify_tok = str(cfg.get("INPUT_APIFY_TOKEN") or "").strip()

    payload = build_payload(mode, targets, max_results)
    provider = "zero-key-preview"

    try:
        if rapid_key:
            provider = "rapidapi"
            url = f"https://{slug}.p.rapidapi.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
            raw = http_post_json(url, {"X-RapidAPI-Key": rapid_key, "X-RapidAPI-Host": f"{slug}.p.rapidapi.com"}, payload)
            records, high_risk = evaluate_risk(raw)
        elif apify_tok:
            provider = "apify"
            url = f"https://api.apify.com/v2/acts/{APIFY_OWNER}~{slug}/run-sync-get-dataset-items"
            raw = http_post_json(url, {"Authorization": f"Bearer {apify_tok}"}, payload)
            records, high_risk = evaluate_risk(raw)
        else:
            records, high_risk = build_preview(mode, targets, max_results)
    except Exception as exc:
        print(f"::warning::Cloud fallback to preview ({provider}): {exc}", file=sys.stderr)
        provider = "zero-key-preview"
        records, high_risk = build_preview(mode, targets, max_results)

    gate_failed = bool(fail_on_high and high_risk > 0)
    status = "failed_gate" if gate_failed else ("completed_preview" if provider == "zero-key-preview" else "completed_cloud")

    report = {
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "actionRepo": "ssl-ct-shadow-it-scanner-action",
        "mode": mode,
        "engineSlug": slug,
        "providerUsed": provider,
        "status": status,
        "recordsAnalyzed": len(records),
        "highRiskCount": high_risk,
        "records": records,
    }

    out_dir = Path(cfg.get("RUNNER_TEMP") or tempfile.gettempdir())
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"{slug}_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md_lines = [
        f"## 🛡️ {meta['title']} (`{mode}`)",
        "",
        f"- **Provider:** `{provider}` | **Audited:** `{len(records)}` | **High-Risk Flags:** `{high_risk}`",
        "",
        "| # | Target | Status | Details |",
        "| :---: | :--- | :---: | :--- |",
    ]
    for i, r in enumerate(records[:15], 1):
        tgt = r.get("target") or r.get("domain") or r.get("vatNumber") or r.get("entityName") or f"Item #{i}"
        rk = r.get("riskLevel") or ("HIGH" if r.get("isSanctioned") else "VERIFIED")
        sm = str(r.get("summary") or r.get("note") or "Cloud verified").replace("|", "/")[:100]
        md_lines.append(f"| {i} | `{tgt}` | **{rk}** | {sm} |")

    if provider == "zero-key-preview":
        md_lines.extend([
            "",
            "---",
            f"⚡ **Upgrade to Live Cloud Data:** [Subscribe on RapidAPI (`BASIC Free` / `PRO $19/mo`)](https://rapidapi.com/b2bquantapis/api/{slug}) • [Apify Store (`Pay-Per-Event`)](https://apify.com/b2b-quant-apis/{slug}) • `pip install git+https://github.com/jesleytassili-glitch/b2b-compliance-python-sdk.git`",
        ])

    summary_md = "\n".join(md_lines) + "\n"
    if cfg.get("GITHUB_STEP_SUMMARY"):
        with open(cfg["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as sf:
            sf.write(summary_md)
    else:
        print(summary_md)

    if cfg.get("GITHUB_OUTPUT"):
        with open(cfg["GITHUB_OUTPUT"], "a", encoding="utf-8") as of:
            of.write(f"status={status}\n")
            of.write(f"provider_used={provider}\n")
            of.write(f"records_analyzed={len(records)}\n")
            of.write(f"high_risk_count={high_risk}\n")
            of.write(f"report_json_path={report_path.as_posix()}\n")

    return (1 if gate_failed else 0), report


if __name__ == "__main__":
    code, _ = execute_gate()
    raise SystemExit(code)
