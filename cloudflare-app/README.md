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
- `STATUS_SIGNING_KEY` — random server-only HMAC key for short-lived VirusTotal polling authorization
- `TURNSTILE_SITE_KEY` — public Turnstile widget key
- `TURNSTILE_SECRET_KEY` — secret server-validation key

The app remains usable for local message and URL analysis when provider keys are missing, but it clearly marks those live checks as unavailable.

## Security controls

- Provider credentials are Cloudflare Worker secrets and are never returned by `/api/config` or bundled into browser JavaScript.
- JSON request bodies are streamed through strict byte limits before parsing.
- Cross-site browser writes, unexpected methods, and non-JSON API submissions are rejected.
- Private, local, reserved, credential-bearing, and sensitive tokenized URLs are not sent to external providers.
- Fresh VirusTotal status polling requires a short-lived HMAC authorization token tied to the submitted analysis.
- HTML responses use nonce-based script CSP in the Workers runtime, anti-framing, no-referrer, browser capability restrictions, origin isolation, MIME protections, and HSTS.
- Turnstile is fail-closed when partially configured and validates token length, hostname, action, and server-side Siteverify success when enabled.

No public application can guarantee immunity from every future attack. Keep dependencies patched, rotate provider keys periodically, review Cloudflare security analytics, and enable Turnstile for production abuse protection.

## Privacy

ScamShield does not intentionally persist submitted message text in an application database. URLs can be shared with configured reputation providers. A new VirusTotal analysis is never automatic and requires explicit user consent because the submitted URL and resulting report may become visible to VirusTotal and its security community.
