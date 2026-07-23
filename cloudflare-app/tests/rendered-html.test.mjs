import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workerUrl = new URL("../dist/server/index.js", import.meta.url);
workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
const { default: worker, RateLimiter } = await import(workerUrl.href);

function createDurableObjectContext() {
  let requests = [];
  const sql = {
    exec(query, ...bindings) {
      if (query.startsWith("DELETE FROM requests")) {
        requests = requests.filter((timestamp) => timestamp > bindings[0]);
      } else if (query.startsWith("INSERT INTO requests")) {
        requests.push(bindings[0]);
      }
      return {
        one() {
          return {
            request_count: requests.length,
            earliest_ms: requests.length ? Math.min(...requests) : null,
          };
        },
      };
    },
  };
  return {
    storage: {
      sql,
      transactionSync(callback) {
        return callback();
      },
    },
  };
}

function createRateLimiterNamespace() {
  const buckets = new Map();
  return {
    getByName(name) {
      return {
        async check(limit, windowSeconds) {
          const now = Date.now();
          const cutoff = now - windowSeconds * 1_000;
          const current = (buckets.get(name) ?? []).filter((timestamp) => timestamp > cutoff);
          if (current.length >= limit) {
            const resetAt = current[0] + windowSeconds * 1_000;
            buckets.set(name, current);
            return {
              allowed: false,
              limit,
              remaining: 0,
              retryAfter: Math.max(1, Math.ceil((resetAt - now) / 1_000)),
              resetAt,
            };
          }
          current.push(now);
          buckets.set(name, current);
          return {
            allowed: true,
            limit,
            remaining: limit - current.length,
            retryAfter: 0,
            resetAt: current[0] + windowSeconds * 1_000,
          };
        },
      };
    },
  };
}

const env = {
  ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
  DISABLE_EXTERNAL_CHECKS: "true",
  RATE_LIMITER: createRateLimiterNamespace(),
};
const context = { waitUntil() {} };

function request(path = "/", init = {}, environment = env) {
  return worker.fetch(new Request(`http://localhost${path}`, init), environment, context);
}

test("renders the finished public product", async () => {
  const response = await request("/", { headers: { accept: "text/html" } });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /ScamShield/);
  assert.match(html, /See the risk/);
  assert.match(html, /Quick Scan/);
  assert.match(html, /Deep Scan/);
  assert.match(html, /scamshield-m2-favicon\.png/);
  assert.match(html, /English/);
  assert.match(html, /German/);
  assert.match(html, /Dutch/);
  assert.match(html, />BIH</);
  assert.match(html, />HRV</);
  assert.match(html, />SRB</);
  assert.match(html, /class="theme-toggle"[^>]*data-i18n-skip/);
  assert.match(html, /<html[^>]*lang="en"[^>]*data-theme="dark"/);
});

test("returns health and security headers", async () => {
  const response = await request("/health");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.match(response.headers.get("content-security-policy") ?? "", /script-src-attr 'none'/);
  assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.ok(response.headers.get("x-request-id"));
  const payload = await response.json();
  assert.equal(payload.status, "ok");
});

test("does not derive public metadata from untrusted forwarded hosts", async () => {
  const response = await request("/", { headers: { accept: "text/html", "x-forwarded-host": "attacker.example" } });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.doesNotMatch(html, /attacker\.example/);
  assert.match(html, /https:\/\/scam\.shield-security\.workers\.dev\/scamshield-project-preview\.png/);
});

test("runs a quick scan with an explainable simple result", async () => {
  const response = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      mode: "quick",
      message: "URGENT: verify your account at https://secure-account-check.xyz/login and enter your password.",
    }),
  });
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.scanMode, "quick");
  assert.equal(payload.riskLevel, "High");
  assert.ok(payload.reasons.length >= 3);
  assert.equal(payload.actions.length, 3);
  assert.equal(payload.links.length, 1);
  assert.ok(payload.analysis.rulesEvaluated > 20);
  assert.equal(payload.analysis.inputType, "Message + URL");
  assert.equal(payload.analysis.signals.some((signal) => signal.name === "Urgency & pressure" && signal.count > 0), true);
  assert.equal(payload.links[0].technical.tld, "xyz");
  assert.equal(payload.links[0].technical.usesHttps, true);
});

test("detects long multiline scam patterns instead of returning a generic category", async () => {
  const scamSamples = [
    {
      expectedType: /Account takeover|Brand impersonation/,
      expectedRisk: /^High$/,
      message: `Your cloud account may get deactivated today due to non-payment.
Payment Method Declined. Your cloud storage is full and your files are no longer being backed up.
Action required: update your payment information immediately. Failure to resolve this within 3 days will result in permanent deletion of your personal data.`,
    },
    {
      expectedType: /Investment \/ crypto/,
      expectedRisk: /^High$/,
      message: `Your withdrawal of 1370 USDT is under review.
You need to pay 10% of the total amount as a deposit before the funds can reach your withdrawal address.
Please pay within 48 hours, otherwise your account will be frozen.`,
    },
    {
      expectedType: /Marketplace \/ payment/,
      expectedRisk: /^High$/,
      message: `Will you be able to pay half now so I can take the listing down as sold?
Can you buy an Apple gift card online now and send the code?`,
    },
    {
      expectedType: /Brand impersonation \/ fake charge/,
      expectedRisk: /^High$/,
      message: `Your Apple Account information has been updated.
Bill Paid For 459 USD Via ApplePay. Dispute Call 9703034342.
If you did not make these changes or believe an unauthorized person accessed your account, contact Apple Support.`,
    },
    {
      expectedType: /Delivery \/ postal/,
      expectedRisk: /^(Medium|High)$/,
      message: `FedEx one day shipping. Shipment is in process.
Shipping subtotal $65.25. Insurance fee $20. Handling fee $30. Total Due $115.25 by CreditCard.`,
    },
    {
      expectedType: /Job scam/,
      expectedRisk: /^(Medium|High)$/,
      message: `Your application for the Data Entry position has been reviewed and we invite you to an online interview.
This remote position offers an hourly rate of $27.25 and paid training. If interested, reply YES.`,
    },
    {
      expectedType: /Prize \/ advance-fee|Investment \/ crypto/,
      expectedRisk: /^High$/,
      message: `MrBeast announces a crypto casino giveaway. Everyone who registers receives a $2,500 bonus and can withdraw it instantly.
Enter promo code GIFT. This post will be deleted in one hour, so don't miss your chance.`,
    },
    {
      expectedType: /Document \/ SMS phishing/,
      expectedRisk: /^(Medium|High)$/,
      message: `You have a document awaiting review. Access it here: https://crgxrl.com/Ajxpjyl Reply STOP to opt-out.`,
    },
  ];

  for (const [index, sample] of scamSamples.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `198.51.100.${index + 10}` },
      body: JSON.stringify({ mode: "quick", message: sample.message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.match(payload.riskLevel, sample.expectedRisk);
    assert.match(payload.scamType, sample.expectedType);
    assert.notEqual(payload.scamType, "No dominant scam pattern");
    assert.ok(payload.analysis.signals.length >= 8);
    assert.ok(payload.analysis.categoryMatches.length > 0);
  }
});

test("Deep Scan works independently without a prior Quick Scan", async () => {
  const response = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "deep", message: "Check https://example.com/account" }),
  });
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.scanMode, "deep");
  assert.equal(payload.deepScan.checkedExistingReport, true);
  assert.equal(payload.providers.some((provider) => provider.name === "VirusTotal"), true);
});

test("enforces a global per-client sliding-window scan limit", async () => {
  const rateEnv = { ...env, RATE_LIMITER: createRateLimiterNamespace() };
  const headers = { "content-type": "application/json", "cf-connecting-ip": "198.51.100.240" };
  const body = JSON.stringify({ mode: "quick", message: "Please review this ordinary message." });

  for (let index = 0; index < 20; index += 1) {
    const response = await request("/api/scan", { method: "POST", headers, body }, rateEnv);
    assert.equal(response.status, 200, `request ${index + 1}`);
    assert.equal(response.headers.get("x-ratelimit-limit"), "20");
    assert.equal(response.headers.get("x-ratelimit-remaining"), String(19 - index));
    assert.ok(response.headers.get("x-ratelimit-reset"));
  }

  const blocked = await request("/api/scan", { method: "POST", headers, body }, rateEnv);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get("x-ratelimit-limit"), "20");
  assert.equal(blocked.headers.get("x-ratelimit-remaining"), "0");
  assert.ok(blocked.headers.get("x-ratelimit-reset"));
  assert.ok(Number(blocked.headers.get("retry-after")) >= 1);

  const otherClient = await request("/api/scan", {
    method: "POST",
    headers: { ...headers, "cf-connecting-ip": "198.51.100.241" },
    body,
  }, rateEnv);
  assert.equal(otherClient.status, 200);
});

test("Durable Object limiter makes an atomic sliding-window decision", () => {
  const limiter = new RateLimiter(createDurableObjectContext(), {});
  assert.deepEqual(
    [limiter.check(2, 60).remaining, limiter.check(2, 60).remaining],
    [1, 0],
  );
  const blocked = limiter.check(2, 60);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.remaining, 0);
  assert.ok(blocked.retryAfter >= 1);
  assert.throws(() => limiter.check(0, 60), RangeError);
  assert.throws(() => limiter.check(2, 0), RangeError);
});

test("fails closed when global request protection is unavailable", async () => {
  const unavailableEnv = {
    ...env,
    RATE_LIMITER: {
      getByName() {
        return { async check() { throw new Error("storage unavailable"); } };
      },
    },
  };
  const response = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.242" },
    body: JSON.stringify({ mode: "quick", message: "Please review this message." }),
  }, unavailableEnv);
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("retry-after"), "5");
  assert.match((await response.json()).error, /protection/i);
});

test("detects brand look-alikes and reports domain intelligence", async () => {
  const response = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.70" },
    body: JSON.stringify({ mode: "quick", message: "Review https://paypa1-secure-login.com/account" }),
  });
  assert.equal(response.status, 200);
  const payload = await response.json();
  const link = payload.links[0];
  assert.equal(link.domainIntelligence.brand.suspectedBrand, "PayPal");
  assert.equal(link.domainIntelligence.brand.officialDomain, "paypal.com");
  assert.equal(link.domainIntelligence.brand.isTyposquat, true);
  assert.equal(link.domainIntelligence.brand.state, "danger");
  assert.ok(link.riskScore >= 72);
  assert.equal(link.domainIntelligence.dns.state, "clear");
  assert.equal(link.domainIntelligence.certificate.source, "Certificate Transparency");
  assert.equal(link.domainIntelligence.certificate.activeRecordCount, 1);
  assert.equal(link.domainIntelligence.redirects.checked, false);
  assert.equal(link.domainIntelligence.redirects.bodyFetched, false);
  assert.equal(link.providers.some((provider) => provider.name === "Brand similarity" && provider.state === "danger"), true);
  assert.equal(link.providers.some((provider) => provider.name === "DNS footprint"), true);
  assert.equal(link.providers.some((provider) => provider.name === "Certificate Transparency"), true);
  assert.equal(link.providers.some((provider) => provider.name === "Redirect path" && provider.state === "not-run"), true);
});

test("does not flag an official monitored brand domain as typosquatting", async () => {
  const response = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.71" },
    body: JSON.stringify({ mode: "quick", message: "Open https://www.paypal.com/security" }),
  });
  assert.equal(response.status, 200);
  const link = (await response.json()).links[0];
  assert.equal(link.domainIntelligence.brand.suspectedBrand, "PayPal");
  assert.equal(link.domainIntelligence.brand.isTyposquat, false);
  assert.equal(link.domainIntelligence.brand.state, "clear");
});

test("resolves RDAP age from the registered parent of a subdomain", async () => {
  const originalFetch = globalThis.fetch;
  const rdapRequests = [];
  globalThis.fetch = async (input) => {
    const url = new URL(input instanceof URL ? input.href : typeof input === "string" ? input : input.url);

    if (url.href === "https://data.iana.org/rdap/dns.json") {
      return Response.json({
        services: [[["com"], ["https://rdap.verisign.com/com/v1/"]]],
      });
    }
    if (url.hostname === "rdap.verisign.com" || url.hostname === "rdap.org") {
      rdapRequests.push(url.href);
      if (url.pathname.endsWith("/docs.github.com")) return Response.json({ errorCode: 404 }, { status: 404 });
      if (url.pathname.endsWith("/github.com")) {
        return Response.json({
          ldhName: "GITHUB.COM",
          events: [{ eventAction: "registration", eventDate: "2007-10-09T18:20:50Z" }],
        }, { headers: { "content-type": "application/rdap+json" } });
      }
      return Response.json({ errorCode: 404 }, { status: 404 });
    }
    if (url.hostname === "cloudflare-dns.com") {
      return Response.json({ Status: 0, AD: true, Answer: [{ name: "docs.github.com", type: 1, TTL: 300, data: "140.82.121.3" }] });
    }
    if (url.hostname === "crt.sh") return Response.json([]);
    throw new Error(`Unexpected external request: ${url.href}`);
  };

  try {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.73" },
      body: JSON.stringify({ mode: "quick", message: "Review https://docs.github.com/en safely." }),
    }, { ...env, DISABLE_EXTERNAL_CHECKS: "false" });
    assert.equal(response.status, 200);
    const link = (await response.json()).links[0];
    const rdap = link.providers.find((provider) => provider.name === "RDAP domain age");
    assert.equal(rdap.state, "clear");
    assert.equal(rdap.label, "Established");
    assert.ok(link.domainAgeDays > 6_000);
    assert.equal(rdapRequests.some((url) => url.endsWith("/docs.github.com")), true);
    assert.equal(rdapRequests.some((url) => url.endsWith("/github.com")), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Deep Scan inspects a bounded redirect path without fetching page content", async () => {
  const response = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.72" },
    body: JSON.stringify({ mode: "deep", message: "Check https://example.com/security" }),
  });
  assert.equal(response.status, 200);
  const link = (await response.json()).links[0];
  assert.equal(link.domainIntelligence.redirects.checked, true);
  assert.equal(link.domainIntelligence.redirects.count, 0);
  assert.equal(link.domainIntelligence.redirects.bodyFetched, false);
  assert.equal(link.domainIntelligence.redirects.state, "clear");
  assert.equal(link.providers.some((provider) => provider.name === "Redirect path" && provider.state === "clear"), true);
});

test("detects obfuscated phishing and multi-signal authority scams without inflating benign text", async () => {
  const cases = [
    {
      message: "URGENT: your acc0unt will be locked. V3rify your l0gin and p.a.s.s.w.o.r.d now at https://account-check.top/login",
      expectedSignal: "Filter evasion",
    },
    {
      message: "This is your CEO. Keep this confidential and do not contact accounting. Buy Apple gift cards immediately and send me the codes.",
      expectedSignal: "Secrecy & isolation",
    },
  ];

  for (const [index, sample] of cases.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `198.51.100.${index + 40}` },
      body: JSON.stringify({ mode: "quick", message: sample.message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.riskLevel, "High");
    assert.equal(payload.analysis.signals.some((signal) => signal.name === sample.expectedSignal && signal.count > 0), true);
  }

  const benign = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.44" },
    body: JSON.stringify({ mode: "quick", message: "Security awareness training example: never share a password and do not click unknown links." }),
  });
  assert.equal(benign.status, 200);
  assert.equal((await benign.json()).riskLevel, "Low");
});

test("detects focused check, identity, gift-card, renewal, and verification-code scams", async () => {
  const cases = [
    {
      type: /Check \/ mobile-deposit scam/,
      level: "High",
      message: "I will pay by check. I will send photos of the front and back, then make the mobile deposit through your banking app.",
    },
    {
      type: /Identity \/ verification phishing/,
      level: "High",
      message: "Complete pre-employment verification within 24 hours. Submit a government-issued photo ID and proof of address to keep the application active.",
    },
    {
      type: /Gift-card impersonation scam/,
      level: "High",
      message: "Keep this team surprise confidential. Buy store gift cards now and send the codes; I will reimburse you.",
    },
    {
      type: /Renewal \/ subscription phishing/,
      level: "Medium",
      message: "Our records indicate your microchip enrollment expired and will show unregistered. Visit the link to renew the registration.",
    },
    {
      type: /Verification-code theft/,
      level: "High",
      message: "Send me your unlock code fast. The verification code expires after 40 seconds and I need it from another phone.",
    },
  ];

  for (const [index, sample] of cases.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `198.51.100.${80 + index}` },
      body: JSON.stringify({ mode: "quick", message: sample.message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.riskLevel, sample.level);
    assert.match(payload.scamType, sample.type);
  }

  const ordinary = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.89" },
    body: JSON.stringify({ mode: "quick", message: "I deposited the rent check in my mobile banking app. The payment cleared normally." }),
  });
  assert.equal(ordinary.status, 200);
  assert.equal((await ordinary.json()).riskLevel, "Low");
});

test("keeps every information-shell label in the translation catalog", async () => {
  const translations = await readFile(new URL("../app/translations.ts", import.meta.url), "utf8");
  const labels = [
    "ScamShield guides",
    "Guide qualities",
    "Decision pipeline",
    "Evidence model",
    "Data boundary",
    "Safety boundary",
    "4 stages",
    "3 risk bands",
    "Consent gated",
    "Human check",
    "Language, URL structure, live reputation, and an explainable recommendation.",
    "The score is built from observable evidence—not an unexplained AI confidence number.",
    "Message analysis stays inside the scan flow; URL reputation checks have visible provider boundaries.",
    "Unknown campaigns, missing context, and provider gaps still require independent verification.",
    "Use these pages to understand what the result means before acting on it.",
    "Paste the complete message for the clearest explanation. No account is required.",
  ];

  for (const label of labels) {
    assert.equal(translations.includes(`["${label}"`), true, label);
  }
});

test("keeps technical result labels in the translation catalog", async () => {
  const translations = await readFile(new URL("../app/translations.ts", import.meta.url), "utf8");
  const labels = [
    "Technical result sections",
    "Evidence",
    "URLs",
    "Providers",
    "IOCs",
    "Local analysis",
    "Live checks",
    "Rules",
    "Lines",
    "Domain",
    "hostname characters",
    "Shortened URL",
    "Direct URL",
    "User-info present",
    "No user-info",
    "Domains",
    "Email addresses",
    "Phone numbers",
    "Crypto wallets",
    "None found",
    "High-confidence signals",
    "Supporting warnings",
    "Clear or neutral signals",
  ];

  for (const label of labels) {
    assert.equal(translations.includes(`["${label}"`), true, label);
  }
});

test("detects high-risk phishing across all supported message-language groups", async () => {
  const samples = [
    {
      language: "German",
      message: "DRINGEND: Ihr Konto wird sofort gesperrt. Bestätigen Sie Ihr Passwort unter https://konto-pruefung.top/login und geben Sie den Sicherheitscode ein.",
    },
    {
      language: "Spanish",
      message: "URGENTE: Su cuenta será bloqueada inmediatamente. Verifique su contraseña en https://verificar-cuenta.top/login y envíe el código de verificación.",
    },
    {
      language: "French",
      message: "URGENT : votre compte sera bloqué immédiatement. Vérifiez votre mot de passe sur https://verification-compte.top/login et envoyez le code de vérification.",
    },
    {
      language: "Dutch",
      message: "DRINGEND: Uw rekening wordt onmiddellijk geblokkeerd. Verifieer uw wachtwoord via https://rekening-controle.top/login en stuur de verificatiecode.",
    },
    {
      language: "Bosnian",
      message: "HITNO: Vaš bankovni račun će biti blokiran odmah. Potvrdite lozinku na https://provjera-racuna.top/login i pošaljite sigurnosni kod.",
    },
    {
      language: "Croatian",
      message: "HITNO: Vaš bankovni račun bit će blokiran odmah. Potvrdite zaporku na https://provjera-racuna.top/login i pošaljite sigurnosni kod.",
    },
    {
      language: "Serbian",
      message: "HITNO: Vaš bankovni nalog biće blokiran odmah. Proverite lozinku na https://provera-naloga.top/login i pošaljite bezbednosni kod.",
    },
  ];

  for (const [index, sample] of samples.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `198.51.100.${index + 60}` },
      body: JSON.stringify({ mode: "quick", message: sample.message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.riskLevel, "High", sample.language);
    assert.equal(payload.analysis.detectedLanguage, sample.language);
    assert.notEqual(payload.scamType, "No specific scam category identified");
  }
});

test("detects localized scam categories beyond credential phishing", async () => {
  const samples = [
    {
      language: "German",
      category: /Brand impersonation \/ fake charge/,
      message: "DRINGEND: Eine unbekannte, nicht autorisierte Abbuchung wurde erkannt. Klicken Sie auf den Link https://rechnung-pruefen.top und widersprechen Sie der Transaktion sofort.",
    },
    {
      language: "Spanish",
      category: /Delivery \/ postal/,
      message: "URGENTE: La entrega ha fallado y debe pagar una tarifa de aduana. Haga clic en el enlace https://entrega-segura.top para completar el pago ahora.",
    },
    {
      language: "French",
      category: /Prize \/ advance-fee/,
      message: "URGENT : vous avez gagné un prix. Payez les frais de dossier et cliquez sur le lien https://prix-reclame.top pour réclamer votre récompense.",
    },
    {
      language: "Dutch",
      category: /Job scam/,
      message: "DRINGEND: Voor deze vacature moet u vooraf betalen. Het sollicitatiegesprek is via WhatsApp; stuur de betaling vandaag om te beginnen.",
    },
    {
      language: "Bosnian",
      category: /Investment \/ crypto/,
      message: "HITNO: Provjerite ponudu. Vaša isplata je blokirana dok ne uplatite naknadu. Ovo ulaganje ima zagarantovanu zaradu; pošaljite novac odmah.",
    },
    {
      language: "Croatian",
      category: /Document \/ SMS phishing/,
      message: "HITNO: Dokument je na čekanju. Otvorite dokument putem poveznice https://dokument-pregled.top i potvrdite zaporku.",
    },
    {
      language: "Serbian",
      category: /Brand impersonation \/ fake charge|Account takeover/,
      message: "HITNO: Na nalogu je neovlašćena transakcija. Proverite bezbednosni kod na https://provera-naloga.top i odmah osporite plaćanje.",
    },
  ];

  for (const [index, sample] of samples.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `203.0.113.${index + 80}` },
      body: JSON.stringify({ mode: "quick", message: sample.message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.match(payload.riskLevel, /^(Medium|High)$/, sample.language);
    assert.equal(payload.analysis.detectedLanguage, sample.language);
    assert.match(payload.scamType, sample.category);
  }
});

test("keeps ordinary multilingual messages low risk while identifying their language", async () => {
  const samples = [
    ["German", "Bitte bringen Sie die Unterlagen morgen zum vereinbarten Termin mit."],
    ["Spanish", "Por favor, recuerde que la reunión comienza mañana a las diez."],
    ["French", "Veuillez apporter les documents à la réunion prévue demain matin."],
    ["Dutch", "Alstublieft, neem de documenten morgen mee naar de afgesproken vergadering."],
    ["Bosnian", "Molim vas, sljedeći sastanak je sutra u deset sati."],
    ["Croatian", "Molim vas, poveznica za sutrašnji sastanak nalazi se u kalendaru."],
    ["Serbian", "Molim vas, sledeći sastanak je sutra u deset sati."],
  ];

  for (const [index, [language, message]] of samples.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `192.0.2.${index + 90}` },
      body: JSON.stringify({ mode: "quick", message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.riskLevel, "Low", language);
    assert.equal(payload.analysis.detectedLanguage, language);
  }
});

test("fresh VirusTotal analysis rejects missing consent", async () => {
  const response = await request("/api/deep/submit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.com", consent: false }),
  });
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /consent/i);
});

test("rejects empty and oversized scans", async () => {
  const empty = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "quick", message: "" }),
  });
  assert.equal(empty.status, 400);

  const oversized = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "quick", message: "x".repeat(10_001) }),
  });
  assert.equal(oversized.status, 413);
});

test("rejects untrusted content types, cross-site writes, and oversized request bodies", async () => {
  const wrongType = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: JSON.stringify({ mode: "quick", message: "hello" }),
  });
  assert.equal(wrongType.status, 415);

  const crossSite = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://attacker.example", "sec-fetch-site": "cross-site" },
    body: JSON.stringify({ mode: "quick", message: "hello" }),
  });
  assert.equal(crossSite.status, 403);

  const oversizedBody = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "quick", message: "x".repeat(50_000) }),
  });
  assert.equal(oversizedBody.status, 413);

  const wrongMethod = await request("/api/scan", { method: "GET" });
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.headers.get("allow"), "POST");
});

test("keeps private URLs local and blocks sensitive external submissions", async () => {
  const localScan = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "deep", message: "Review http://192.168.1.10/private" }),
  });
  assert.equal(localScan.status, 200);
  const localPayload = await localScan.json();
  assert.equal(localPayload.links[0].providers.filter((provider) => provider.name !== "Brand similarity").every((provider) => provider.label === "Protected"), true);
  assert.equal(localPayload.links[0].providers.some((provider) => provider.name === "Brand similarity"), true);

  const providerEnv = { ...env, VIRUSTOTAL_API_KEY: "test-provider-secret" };
  const privateSubmit = await request("/api/deep/submit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "http://127.0.0.1/admin", consent: true }),
  }, providerEnv);
  assert.equal(privateSubmit.status, 400);
  assert.match((await privateSubmit.json()).error, /private|local|reserved/i);

  const credentialSubmit = await request("/api/deep/submit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.com/reset?token=private-value", consent: true }),
  }, providerEnv);
  assert.equal(credentialSubmit.status, 400);
  assert.match((await credentialSubmit.json()).error, /token|credential/i);
});

test("requires a signed token before spending provider quota on status polling", async () => {
  const response = await request("/api/deep/status?id=known-analysis-id", {}, { ...env, VIRUSTOTAL_API_KEY: "test-provider-secret" });
  assert.equal(response.status, 403);
  assert.match((await response.json()).error, /token/i);
});

test("runtime config exposes no private provider configuration", async () => {
  const response = await request("/api/config");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { turnstileSiteKey: null, turnstileConfigured: false });
});

test("renders all transparency pages", async () => {
  const pages = {
    "/how-it-works": "From suspicious message to clear next step",
    "/methodology": "A score built from visible evidence",
    "/privacy": "Privacy boundaries you can understand",
    "/limitations": "What a scan can—and cannot—prove",
  };

  for (const [path, heading] of Object.entries(pages)) {
    const response = await request(path, { headers: { accept: "text/html" } });
    assert.equal(response.status, 200, path);
    const html = await response.text();
    assert.match(html, /SCAMSHIELD/);
    assert.match(html, new RegExp(heading));
    assert.match(html, /info-tabs/);
    assert.match(html, /info-visual/);
    assert.match(html, /info-orbit-outer/);
    assert.match(html, /info-orbit-inner/);
    assert.match(html, /info-toc/);
    assert.match(html, /aria-current="page"/);
  }
});
