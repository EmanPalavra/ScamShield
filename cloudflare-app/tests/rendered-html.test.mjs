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
  RATE_LIMIT_SIGNING_KEY: "test-rate-limit-signing-key-32-bytes-minimum",
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
  assert.match(html, /class="theme-toggle[^"]*"[^>]*data-i18n-skip/);
  assert.doesNotMatch(html, /theme-toggle-label/);
  assert.match(html, /class="settings-picker"/);
  assert.match(html, /role="switch"[^>]*aria-checked="false"/);
  assert.match(html, /Anonymous diagnostics/);
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

test("records only allow-listed anonymous diagnostic fields after consent", async () => {
  const points = [];
  const diagnosticEnv = {
    ...env,
    DIAGNOSTICS: {
      writeDataPoint(point) {
        points.push(point);
      },
    },
  };
  const response = await request("/api/diagnostics", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.61" },
    body: JSON.stringify({
      consent: true,
      event: "result_feedback",
      mode: "deep",
      durationMs: 1842,
      riskLevel: "High",
      detectedLanguage: "Bosnian",
      riskPercent: 91,
      providerCompleted: 3,
      providerTotal: 4,
      linkCount: 1,
      feedback: "should_be_safer",
    }),
  }, diagnosticEnv);

  assert.equal(response.status, 202);
  assert.deepEqual(await response.json(), { recorded: true });
  assert.equal(points.length, 1);
  assert.deepEqual(points[0].indexes, ["result_feedback"]);
  assert.deepEqual(points[0].blobs, ["v1", "result_feedback", "deep", "High", "Bosnian", "should_be_safer", "none"]);
  assert.deepEqual(points[0].doubles, [1842, 91, 3, 4, 1]);
  assert.doesNotMatch(JSON.stringify(points[0]), /198\.51\.100\.61|message|url/i);
});

test("rejects diagnostic payloads without consent or with content fields", async () => {
  const points = [];
  const diagnosticEnv = {
    ...env,
    DIAGNOSTICS: { writeDataPoint: (point) => points.push(point) },
  };
  const withoutConsent = await request("/api/diagnostics", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ event: "scan_error", mode: "quick", durationMs: 20, errorCategory: "network" }),
  }, diagnosticEnv);
  assert.equal(withoutConsent.status, 400);

  const withMessage = await request("/api/diagnostics", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      consent: true,
      event: "scan_complete",
      mode: "quick",
      durationMs: 20,
      message: "private input",
    }),
  }, diagnosticEnv);
  assert.equal(withMessage.status, 400);
  assert.equal(points.length, 0);
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

test("uses stable, non-enumerable HMAC identifiers for rate-limit buckets", async () => {
  const bucketNames = [];
  const recordingNamespace = {
    getByName(name) {
      bucketNames.push(name);
      return {
        async check(limit) {
          return { allowed: true, limit, remaining: limit - 1, retryAfter: 0, resetAt: Date.now() + 60_000 };
        },
      };
    },
  };
  const protectedEnv = { ...env, RATE_LIMITER: recordingNamespace };
  const scan = (ip) => request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": ip },
    body: JSON.stringify({ mode: "quick", message: "ordinary message" }),
  }, protectedEnv);

  assert.equal((await scan("198.51.100.21")).status, 200);
  assert.equal((await scan("198.51.100.21")).status, 200);
  assert.equal((await scan("198.51.100.22")).status, 200);
  assert.equal(bucketNames[0], bucketNames[1]);
  assert.notEqual(bucketNames[0], bucketNames[2]);
  assert.doesNotMatch(bucketNames.join(" "), /198\.51\.100\./);
  assert.match(bucketNames[0], /^v1:\d+:[a-f0-9]{64}:quick$/);
});

test("fails closed in production when no rate-limit signing secret is available", async () => {
  const environmentWithoutSigningKey = { ...env };
  delete environmentWithoutSigningKey.RATE_LIMIT_SIGNING_KEY;
  const response = await worker.fetch(new Request("https://scam.example/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.25" },
    body: JSON.stringify({ mode: "quick", message: "ordinary message" }),
  }), environmentWithoutSigningKey, context);
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /protection/i);
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

test("distinguishes routine account onboarding from credential phishing", async () => {
  const legitimateMessage = `Translated: Dutch
English
Translate can make mistakes, so verify translations
Dear Person,
An account has been created for you to use SpotonMedics for FysioQualis.

You can log in via login.spotonmedics.nl with the following login details:

Username    Person
Password    Click here to set the password for the first time
Yours sincerely,
HCI SpotOnMedics support team

This message was automatically generated. Please contact FysioQualis if you have any questions.`;

  const legitimate = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.190" },
    body: JSON.stringify({ mode: "quick", message: legitimateMessage }),
  });
  assert.equal(legitimate.status, 200);
  const legitimateResult = await legitimate.json();
  assert.equal(legitimateResult.riskLevel, "Low");
  assert.ok(legitimateResult.riskPercent < 34);
  assert.equal(legitimateResult.scamType, "Routine account onboarding / access notice");
  assert.match(legitimateResult.reasons[0], /routine account-onboarding/i);
  assert.equal(legitimateResult.analysis.context.routineAccountNotice, true);
  assert.equal(legitimateResult.analysis.signals.find((signal) => signal.name === "Sensitive information").count, 0);
  assert.equal(legitimateResult.analysis.signals.find((signal) => signal.name === "Forced call to action").state, "clear");
  assert.equal(legitimateResult.links[0].domain, "login.spotonmedics.nl");

  const phishing = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.191" },
    body: JSON.stringify({
      mode: "quick",
      message: "URGENT: Your account will be suspended today. Verify your password and send the verification code immediately at https://secure-account-check.xyz/login.",
    }),
  });
  assert.equal(phishing.status, 200);
  const phishingResult = await phishing.json();
  assert.equal(phishingResult.riskLevel, "High");
  assert.ok(phishingResult.riskPercent >= 76);
  assert.equal(phishingResult.analysis.context.routineAccountNotice, false);
  assert.ok(phishingResult.analysis.signals.find((signal) => signal.name === "Sensitive information").count >= 1);
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

test("uses the local model as a conservative fallback for wording missed by rules", async () => {
  const response = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.90" },
    body: JSON.stringify({
      mode: "quick",
      message: "I am contacting you about an unclaimed allocation registered under your surname. We can arrange release after the administrative form is completed.",
    }),
  });
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.riskLevel, "Medium");
  assert.equal(payload.analysis.model.raisedAlert, true);
  assert.ok(payload.analysis.model.probability >= 0.995);
  assert.match(payload.reasons[0], /local statistical model/i);
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
    "The score is built from observable evidence, not an unexplained AI confidence number.",
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

test("detects calibrated real-world multilingual scam wording without flagging routine messages", async () => {
  const scamSamples = [
    ["German", /Delivery \/ postal/, "Ihr Paket wurde im Verteilerzentrum angehalten. Verfolgen Sie Ihre Sendung hier: https://example.invalid/sendung"],
    ["French", /Brand impersonation \/ fake charge/, "Votre achat de 594,98 EUR a été enregistré. Si vous n'avez pas initié ce paiement, contactez vite le service opposition."],
    ["Dutch", /Account takeover \/ phishing/, "DigiD update: controle vereist. Controleer en bevestig uw gegevens via https://example.invalid/digid"],
    ["Serbian", /Delivery \/ postal/, "Ваш пакет подлеже царинама. Посетите https://example.invalid/posta да пратите процедуру."],
    ["English", /Account takeover \/ phishing/, "Your Apple ID is due to expire today. Confirm your Apple ID at https://example.invalid/apple"],
  ];
  const legitimateSamples = [
    ["German", "Dein Paket ist angekommen. Ich bringe es dir morgen nach der Arbeit mit."],
    ["French", "J'ai bien reçu ton colis, merci beaucoup pour le cadeau."],
    ["Dutch", "Je pakket is aangekomen; ik neem het morgen mee naar kantoor."],
    ["Bosnian", "Paket je stigao i nalazi se kod mene, donijet ću ga sutra."],
    ["English", "Your order arrived today and the receipt is saved in your account history."],
  ];

  for (const [index, [language, category, message]] of scamSamples.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `198.51.100.${index + 100}` },
      body: JSON.stringify({ mode: "quick", message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.match(payload.riskLevel, /^(Medium|High)$/, language);
    assert.equal(payload.analysis.detectedLanguage, language);
    assert.match(payload.scamType, category);
  }

  for (const [index, [language, message]] of legitimateSamples.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `203.0.113.${index + 100}` },
      body: JSON.stringify({ mode: "quick", message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.riskLevel, "Low", language);
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

test("sanitizes sensitive URL values unless exact external sharing is explicitly allowed", async () => {
  const message = "Review https://example.com/reset?token=private-value&campaign=notice";
  const privacySafe = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "deep", message }),
  });
  assert.equal(privacySafe.status, 200);
  const safePayload = await privacySafe.json();
  assert.equal(safePayload.privacy.sensitiveUrlDetected, true);
  assert.equal(safePayload.privacy.sanitizedUrls, 1);
  assert.equal(safePayload.privacy.fullSensitiveUrlsShared, 0);
  assert.equal(safePayload.links[0].externalSharing.mode, "sanitized");
  assert.doesNotMatch(safePayload.links[0].externalSharing.providerUrl, /private-value/);
  assert.match(safePayload.links[0].externalSharing.providerUrl, /campaign=notice/);

  const exact = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "deep", message, sensitiveUrlConsent: true }),
  });
  assert.equal(exact.status, 200);
  const exactPayload = await exact.json();
  assert.equal(exactPayload.privacy.fullSensitiveUrlsShared, 1);
  assert.equal(exactPayload.links[0].externalSharing.mode, "full-with-consent");
  assert.match(exactPayload.links[0].externalSharing.providerUrl, /token=private-value/);
});

test("accepts a sensitive fresh VirusTotal submission only with both explicit consents", async () => {
  const originalFetch = globalThis.fetch;
  let submittedBody = "";
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    if (url === "https://www.virustotal.com/api/v3/urls") {
      submittedBody = String(init.body ?? "");
      return Response.json({ data: { id: "consented-sensitive-analysis" } });
    }
    return originalFetch(input, init);
  };

  try {
    const response = await request("/api/deep/submit", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.44" },
      body: JSON.stringify({
        url: "https://example.com/reset?token=private-value",
        consent: true,
        sensitiveUrlConsent: true,
      }),
    }, { ...env, VIRUSTOTAL_API_KEY: "test-provider-secret" });
    assert.equal(response.status, 200);
    assert.match(submittedBody, /token%3Dprivate-value/);
  } finally {
    globalThis.fetch = originalFetch;
  }
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
    "/limitations": "What a scan can and cannot prove",
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

test("detects current authority-reported scam campaigns without flagging similar everyday messages", async () => {
  const scams = [
    ["English", "USPS: Your package has unpaid postage. Update shipping preferences: https://example.invalid/usps"],
    ["German", "Ihre pushTAN Registrierung läuft in 12 Stunden ab. Hier erneuern: https://example.invalid/tan"],
    ["French", "Assurance Maladie : votre compte sera restreint. Confirmez vos informations: https://example.invalid/ameli"],
    ["Dutch", "iDEAL: een overboeking van €2.850 is goedgekeurd. Herkent u deze niet? Bel direct 020-XXX-XXXX."],
    ["Bosnian", "Pošta: dostava paketa nije uspjela zbog nepotpune adrese. Ažurirajte podatke: https://example.invalid/adresa"],
  ];
  const legitimate = [
    ["English", "My USPS package arrived and I saved the delivery receipt."],
    ["German", "Meine neue Handynummer ist jetzt im Familienchat gespeichert."],
    ["French", "Mon compte Ameli fonctionne et aucun changement n'est demandé."],
    ["Dutch", "De overboeking die ik zelf deed staat correct in mijn rekeningoverzicht."],
    ["Bosnian", "Paket je stigao; adresa na potvrdi je ispravna."],
  ];

  for (const [index, [language, message]] of scams.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `198.51.100.${index + 140}` },
      body: JSON.stringify({ mode: "quick", message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.match(payload.riskLevel, /^(Medium|High)$/, language);
  }

  for (const [index, [language, message]] of legitimate.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `203.0.113.${index + 140}` },
      body: JSON.stringify({ mode: "quick", message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.riskLevel, "Low", language);
  }
});

test("detects subtle German and BHS campaigns while preserving localized hard negatives", async () => {
  const scams = [
    ["German banking", "Ihre Registrierung für die Banking-to-go-App läuft in Kürze ab. Hier registrieren: https://example.invalid/banking"],
    ["German delivery", "IHR PAKETZUSTELLER: Es ist ein Fehler aufgetreten. Überprüfen Sie Ihre Sendungsverfolgung und zahlen Sie die Zollgebühren, um die Lieferung fortzusetzen: https://example.invalid/paket"],
    ["German fine", "Sie haben einen unbezahlten Strafzettel. Bitte bezahlen Sie ihn umgehend: https://example.invalid/strafe"],
    ["German family", "Mein Telefon ist kaputt. Lösche meine alte Nummer, speichere diese hier und schreib mir auf WhatsApp."],
    ["BHS banking", "ASA Banka: Vaša kartica je privremeno ograničena. Potvrdite podatke putem linka: https://example.invalid/kartica"],
    ["BHS delivery", "BH Pošta: Pošiljka nije isporučena zbog neplaćenih carinskih dažbina. Platite naknadu: https://example.invalid/posta"],
    ["BHS transaction", "Banka: Zabilježena je nepoznata transakcija. Ako ovo niste vi, pozovite broj 061123456."],
    ["BHS family", "Mama, telefon mi je pokvaren i ovo je moj novi broj. Pošalji mi novac za račun."],
    ["BHS Cyrillic delivery", "DHL: Ваш пакет чека у нашим складиштима. Потврдите своју адресу и платите трошкове слања да бисте започели испоруку."],
    ["BHS Cyrillic subscription", "NTFX: Ваше последње задужење је одбијено. Да бисте наставили да користите наше услуге посетите портал."],
  ];
  const legitimate = [
    ["German OTP", "Ihre TAN lautet 481920. Geben Sie TAN und Sicherheitscodes niemals an andere Personen weiter."],
    ["German delivery", "Das Paket wurde heute erfolgreich an Ihrer Adresse zugestellt."],
    ["German banking", "Ihre Kartenzahlung über 24,90 EUR wurde erfolgreich ausgeführt. Sie müssen nichts unternehmen."],
    ["German family", "Meine neue Handynummer ist bereits im Familienchat gespeichert."],
    ["BHS OTP", "Vaš jednokratni sigurnosni kod je 481920. Nikome ga ne dijelite."],
    ["BHS delivery", "Paket je danas uspješno dostavljen na vašu adresu."],
    ["BHS banking", "Kartična transakcija od 24,90 KM je uspješno izvršena. Nije potrebna nikakva radnja."],
    ["BHS appointment", "Termin u banci je u utorak u 10 sati. Nije potrebno odgovoriti na poruku."],
    ["BHS Cyrillic delivery", "Ваша пошиљка је успешно достављена на адресу."],
    ["BHS Cyrillic OTP", "Ваш сигурносни код је 481920. Никоме га не делите."],
  ];

  for (const [index, [name, message]] of scams.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `198.51.100.${index + 160}` },
      body: JSON.stringify({ mode: "quick", message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.match(payload.riskLevel, /^(Medium|High)$/, name);
  }

  for (const [index, [name, message]] of legitimate.entries()) {
    const response = await request("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json", "cf-connecting-ip": `203.0.113.${index + 160}` },
      body: JSON.stringify({ mode: "quick", message }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.riskLevel, "Low", name);
  }
});
