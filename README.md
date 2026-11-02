# 🛡️ SSL/TLS CT Log, SPF/DMARC & Shadow-IT Attack Surface Scanner

[![Marketplace Release](https://img.shields.io/github/v/release/jesleytassili-glitch/ssl-ct-shadow-it-scanner-action?color=brightgreen&label=Marketplace%20Release)](https://github.com/jesleytassili-glitch/ssl-ct-shadow-it-scanner-action/releases/tag/v1.0.0)
[![Official MCP Registry](https://img.shields.io/badge/Official_MCP_Registry-io.github.jesleytassili-glitch-6366F1)](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.jesleytassili-glitch)
[![RapidAPI Hub](https://img.shields.io/badge/RapidAPI-@b2bquantapis-0055FF)](https://rapidapi.com/b2bquantapis/api/b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

Scheduled CI/CD external attack surface scanner for Certificate Transparency subdomains, expired SSL, SPF/DMARC & RDAP.

## 🚀 Quick Start (`.github/workflows/compliance.yml`)

```yaml
name: Automated Compliance Audit
on:
  pull_request:
  schedule:
    - cron: '0 7 * * 1'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SSL/TLS CT Log, SPF/DMARC & Shadow-IT Attack Surface Scanner
        uses: jesleytassili-glitch/ssl-ct-shadow-it-scanner-action@v1
        with:
          mode: 'ct-subdomains'
          targets: 'github.com,cloudflare.com'
          rapidapi_key: ${{ secrets.RAPIDAPI_KEY }}
```

## 📊 Available Audit Modes

- `ct-subdomains` — SSL/TLS Certificate Transparency & Shadow-IT Subdomain Audit ([RapidAPI](https://rapidapi.com/b2bquantapis/api/b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor) | [Apify](https://apify.com/b2b-quant-apis/b2b-ssl-tls-ct-log-subdomain-attack-surface-auditor))
- `email-dns-security` — SPF, DMARC, BIMI & MX Anti-Spoofing Security Audit ([RapidAPI](https://rapidapi.com/b2bquantapis/api/global-b2b-email-domain-security-auditor) | [Apify](https://apify.com/b2b-quant-apis/global-b2b-email-domain-security-auditor))
- `rdap-whois-recon` — ICANN RDAP Domain Registration & Brand Impersonation Recon ([RapidAPI](https://rapidapi.com/b2bquantapis/api/icann-rdap-domain-whois-brand-recon) | [Apify](https://apify.com/b2b-quant-apis/icann-rdap-domain-whois-brand-recon))

## 📦 Programmatic SDKs & Local MCP Server

- **Python SDK:** `pip install https://github.com/jesleytassili-glitch/b2b-compliance-python-sdk/releases/download/v1.0.0/b2b_compliance_sdk-1.0.0-py3-none-any.whl`
- **Node.js / Claude / Cursor MCP (`stdio`):** `npx --yes github:jesleytassili-glitch/b2b-compliance-mcp-cli`
