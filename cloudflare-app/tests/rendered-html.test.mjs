import assert from "node:assert/strict";
import test from "node:test";

const workerUrl = new URL("../dist/server/index.js", import.meta.url);
workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
const { default: worker } = await import(workerUrl.href);

const env = {
  ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
  DISABLE_EXTERNAL_CHECKS: "true",
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
  assert.equal(localPayload.links[0].providers.every((provider) => provider.label === "Protected"), true);

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
