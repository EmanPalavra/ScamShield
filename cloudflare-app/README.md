# ScamShield Cloudflare application

This is the public, Cloudflare Worker-compatible ScamShield application.

## What it includes

- independent Quick Scan and Deep Scan flows
- concurrent Google Safe Browsing, RDAP, and VirusTotal checks
- existing VirusTotal report lookup before any new submission
- explicit privacy consent before fresh VirusTotal analysis
- fresh-analysis submission and status polling
- Simple View and Analyst View tabs
- request limits, input limits, provider timeouts, caching, security headers, and `/health`
- How it works, Privacy, Methodology, and Limitations pages
- optional server-validated Cloudflare Turnstile protection

## Local development

Copy `.env.example` to `.env.local` and set only the providers you want to test. Never commit API keys.

```powershell
pnpm install
pnpm run dev
pnpm run build
pnpm test
```

## Hosted variables

- `GOOGLE_API_KEY` — Google Safe Browsing v5
- `VIRUSTOTAL_API_KEY` — VirusTotal v3 URL reports and consent-based new analyses
- `TURNSTILE_SITE_KEY` — public Turnstile widget key
- `TURNSTILE_SECRET_KEY` — secret server-validation key

The app remains usable for local message and URL analysis when provider keys are missing, but it clearly marks those live checks as unavailable.

## Privacy

ScamShield does not intentionally persist submitted message text in an application database. URLs can be shared with configured reputation providers. A new VirusTotal analysis is never automatic and requires explicit user consent because the submitted URL and resulting report may become visible to VirusTotal and its security community.
