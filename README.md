# ScamShield

ScamShield is a single Cloudflare Worker application for explainable scam-risk analysis of suspicious messages and URLs.

The active project lives in `cloudflare-app/`. The root `app.py` is only a compatibility launcher, so both of these commands start the same current application:

```powershell
python app.py
```

```powershell
cd cloudflare-app
pnpm run dev
```

There is no separate Flask version anymore.

## Features

- independent Quick Scan and Deep Scan flows
- explainable message-pattern and URL-structure analysis
- Google Safe Browsing, RDAP, and VirusTotal provider checks
- explicit consent before a fresh VirusTotal submission
- signed VirusTotal status polling
- Simple and Analyst result views
- responsive dark and light themes
- How it works, Methodology, Privacy, and Limitations pages
- bounded inputs, private-URL protection, rate limits, CSP, and security headers

## Local setup

Requirements:

- Node.js 22.13 or newer
- pnpm, Corepack, or npm
- Python only if you want to use the `python app.py` launcher

Install dependencies once:

```powershell
cd cloudflare-app
pnpm install
```

Copy `cloudflare-app/.env.example` to `cloudflare-app/.env.local` and add only the provider keys needed for local testing. Never commit real keys.

Supported variables:

```env
GOOGLE_API_KEY=
VIRUSTOTAL_API_KEY=
STATUS_SIGNING_KEY=
TURNSTILE_SITE_KEY=
TURNSTILE_SECRET_KEY=
```

The old root `.env` file is not read by the current application.

## Validation

Run from `cloudflare-app/`:

```powershell
pnpm run lint
pnpm exec tsc --noEmit
pnpm test
```

## Project structure

- `cloudflare-app/app/` — interface, result dashboard, themes, and transparency pages
- `cloudflare-app/worker/scanner.ts` — scan engine and provider orchestration
- `cloudflare-app/worker/index.ts` — Worker entry point and response security
- `cloudflare-app/tests/` — application and security regression tests
- `app.py` — launcher for the same `cloudflare-app` development server

## Production

The production Worker is deployed at:

[https://scam.shield-security.workers.dev](https://scam.shield-security.workers.dev)

Provider credentials must remain Cloudflare Worker secrets. Do not place production secret values in source files or browser code.
