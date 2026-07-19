import assert from "node:assert/strict";
import test from "node:test";

const workerUrl = new URL("../dist/server/index.js", import.meta.url);
workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
const { default: worker } = await import(workerUrl.href);

const env = {
  ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
  DISABLE_EXTERNAL_CHECKS: "true",
};
const context = { waitUntil() {}, passThroughOnException() {} };

function request(path = "/", init = {}) {
  return worker.fetch(new Request(`http://localhost${path}`, init), env, context);
}

test("renders the finished public product", async () => {
  const response = await request("/", { headers: { accept: "text/html" } });
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /ScamShield/);
  assert.match(html, /Pause before you trust the message/);
  assert.match(html, /Quick Scan/);
  assert.match(html, /Deep Scan/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Your site is taking shape/i);
});

test("returns health and security headers", async () => {
  const response = await request("/health");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  const payload = await response.json();
  assert.equal(payload.status, "ok");
  assert.equal(payload.runtime, "cloudflare-worker");
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
  assert.equal(payload.reasons.length, 3);
  assert.equal(payload.actions.length, 3);
  assert.equal(payload.links.length, 1);
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

test("renders all transparency pages", async () => {
  for (const path of ["/how-it-works", "/privacy", "/methodology", "/limitations"]) {
    const response = await request(path, { headers: { accept: "text/html" } });
    assert.equal(response.status, 200, path);
    assert.match(await response.text(), /SCAMSHIELD/);
  }
});
