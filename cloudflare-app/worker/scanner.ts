import { analyzeDomainIntelligence, type DomainIntelligence } from "./domain-intelligence";
import { sanitizeDiagnosticPayload, writeDiagnostic, type DiagnosticsEnv } from "./diagnostics";
import type { RateLimitDecision, RateLimiter } from "./rate-limiter";
import {
  authorityPatterns,
  benignContextPatterns,
  callToActionPatterns,
  categoryRules,
  consequencePatterns,
  credentialPatterns,
  credentialRequestPatterns,
  evasionPatterns,
  impersonationPatterns,
  paymentPatterns,
  rewardPatterns,
  routineAccountNoticePatterns,
  secrecyPatterns,
  shorteners,
  suspiciousTlds,
  urgencyPatterns,
} from "./scanner/message-rules";
import { extractUrls, messageAnalysis } from "./scanner/message-analysis";

export interface ScannerEnv extends DiagnosticsEnv {
  RATE_LIMITER: DurableObjectNamespace<RateLimiter>;
  GOOGLE_API_KEY?: string;
  VIRUSTOTAL_API_KEY?: string;
  STATUS_SIGNING_KEY?: string;
  RATE_LIMIT_SIGNING_KEY?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  DISABLE_EXTERNAL_CHECKS?: string;
}

export interface ScannerContext {
  waitUntil(promise: Promise<unknown>): void;
}

type RiskLevel = "Low" | "Medium" | "High";
type ProviderState = "clear" | "warning" | "danger" | "unavailable" | "not-run";

interface ProviderResult {
  name: string;
  state: ProviderState;
  label: string;
  detail: string;
  configured: boolean;
}

interface LinkReport {
  url: string;
  domain: string;
  riskScore: number;
  reasons: string[];
  providers: ProviderResult[];
  domainAgeDays: number | null;
  virusTotal: {
    found: boolean;
    stats: Record<string, number> | null;
    lastAnalysisDate: number | null;
  } | null;
  externalSharing: {
    mode: "standard" | "sanitized" | "full-with-consent";
    sensitiveParameters: string[];
    providerUrl: string;
  };
  domainIntelligence: DomainIntelligence;
  technical: {
    protocol: "HTTP" | "HTTPS";
    tld: string;
    usesHttps: boolean;
    isIpAddress: boolean;
    isPunycode: boolean;
    isShortener: boolean;
    hasUserInfo: boolean;
    hostnameLength: number;
    pathDepth: number;
    queryParameters: number;
  };
}

const MAX_MESSAGE_LENGTH = 10_000;
const MAX_URLS = 3;
const MAX_URL_LENGTH = 2_048;
const MAX_SCAN_BODY_BYTES = 48 * 1_024;
const MAX_DEEP_BODY_BYTES = 8 * 1_024;
const MAX_DIAGNOSTICS_BODY_BYTES = 4 * 1_024;
const REQUEST_TIMEOUT_MS = 4_500;
const PROVIDER_JSON_LIMIT_BYTES = 256 * 1_024;
const STATUS_TOKEN_TTL_SECONDS = 30 * 60;
const TURNSTILE_ACTION = "turnstile-spin-v2";

function jsonResponse(payload: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function cleanMessage(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function isEnabled(value: string | undefined): boolean {
  return value?.toLowerCase() === "true";
}

function getClientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "local";
}

function rateLimitSecret(request: Request, env: ScannerEnv) {
  const configured = env.RATE_LIMIT_SIGNING_KEY
    ?? env.STATUS_SIGNING_KEY
    ?? env.TURNSTILE_SECRET_KEY
    ?? env.VIRUSTOTAL_API_KEY
    ?? env.GOOGLE_API_KEY;
  if (configured) {
    if (configured.length < 32) throw new Error("Rate-limit signing material is too short.");
    return configured;
  }

  const hostname = new URL(request.url).hostname.toLowerCase();
  if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]") {
    return "scamshield-local-development-rate-limit-key";
  }
  throw new Error("Rate-limit signing material is not configured.");
}

async function getRateKey(request: Request, env: ScannerEnv, action: string) {
  const secret = rateLimitSecret(request, env);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const rotationDay = Math.floor(Date.now() / 86_400_000);
  const payload = `scamshield-rate-limit-v1:${rotationDay}:${getClientIp(request)}`;
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  const digest = [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `v1:${rotationDay}:${digest}:${action}`;
}

async function checkRateLimit(
  request: Request,
  env: ScannerEnv,
  action: string,
  limit: number,
  windowSeconds: number,
) {
  const key = await getRateKey(request, env, action);
  return env.RATE_LIMITER.getByName(key).check(limit, windowSeconds);
}

function rateLimitUnavailable() {
  return jsonResponse(
    { error: "Request protection is temporarily unavailable. Please try again shortly." },
    503,
    { "retry-after": "5" },
  );
}

function rateLimitHeaders(rate: RateLimitDecision) {
  return {
    "x-ratelimit-limit": String(rate.limit),
    "x-ratelimit-remaining": String(rate.remaining),
    "x-ratelimit-reset": String(Math.ceil(rate.resetAt / 1_000)),
  };
}

async function validateTurnstile(request: Request, env: ScannerEnv, token: unknown) {
  const hasSiteKey = Boolean(env.TURNSTILE_SITE_KEY);
  const hasSecret = Boolean(env.TURNSTILE_SECRET_KEY);
  if (!hasSiteKey && !hasSecret) return { valid: true, configured: false, misconfigured: false };
  if (!hasSiteKey || !hasSecret) return { valid: false, configured: true, misconfigured: true };
  if (typeof token !== "string" || !token.trim() || token.length > 2_048) {
    return { valid: false, configured: true, misconfigured: false };
  }

  try {
    const response = await fetchWithTimeout("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secret: env.TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: getClientIp(request),
        idempotency_key: crypto.randomUUID(),
      }),
    });
    const result = await readProviderJson(response) as { success?: boolean; hostname?: string; action?: string } | null;
    const expectedHostname = new URL(request.url).hostname;
    return {
      valid: response.ok && result?.success === true && result.hostname === expectedHostname && result.action === TURNSTILE_ACTION,
      configured: true,
      misconfigured: false,
    };
  } catch {
    return { valid: false, configured: true, misconfigured: false };
  }
}

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isJsonContentType(request: Request) {
  return /^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "");
}

async function readBoundedText(stream: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<string | null> {
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("body too large").catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

type ParsedJsonObject = { body: Record<string, unknown> | null; response: Response | null };

async function parseJsonObject(request: Request, maxBytes: number): Promise<ParsedJsonObject> {
  if (!isJsonContentType(request)) {
    return { body: null, response: jsonResponse({ error: "Content-Type must be application/json." }, 415) };
  }

  const declaredLength = request.headers.get("content-length");
  if (declaredLength) {
    const length = Number(declaredLength);
    if (!Number.isFinite(length) || length < 0) {
      return { body: null, response: jsonResponse({ error: "Invalid Content-Length." }, 400) };
    }
    if (length > maxBytes) {
      return { body: null, response: jsonResponse({ error: "Request body is too large." }, 413) };
    }
  }

  const text = await readBoundedText(request.body, maxBytes);
  if (text === null) return { body: null, response: jsonResponse({ error: "Request body is too large or invalid." }, 413) };

  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("JSON object required");
    return { body: value as Record<string, unknown>, response: null };
  } catch {
    return { body: null, response: jsonResponse({ error: "Invalid JSON request." }, 400) };
  }
}

async function readProviderJson(response: Response): Promise<Record<string, unknown> | null> {
  const text = await readBoundedText(response.body, PROVIDER_JSON_LIMIT_BYTES);
  if (text === null) return null;
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function isTrustedWriteRequest(request: Request) {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && !["same-origin", "same-site", "none"].includes(fetchSite)) return false;
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function parseIpv4(hostname: string): number[] | null {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return null;
  const parts = hostname.split(".").map(Number);
  return parts.every((part) => part >= 0 && part <= 255) ? parts : null;
}

function isPrivateOrReservedAddress(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const ipv4 = parseIpv4(normalized);
  if (ipv4) {
    const [a, b, c] = ipv4;
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && [0, 2].includes(c)) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113);
  }
  if (!normalized.includes(":")) return false;
  if (normalized === "::" || normalized === "::1" || normalized.startsWith("ff")) return true;
  if (/^f[cd]/.test(normalized) || /^fe[89ab]/.test(normalized)) return true;
  const mappedIpv4 = normalized.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  return mappedIpv4 ? isPrivateOrReservedAddress(mappedIpv4) : false;
}

const SENSITIVE_QUERY_PARAMETER = /^(?:access_?token|auth|authorization|code|credential|jwt|otp|pass(?:word|code)?|reset(?:_?token)?|session(?:id)?|signature|sig|secret|token)$/i;

function sensitiveQueryParameters(value: string) {
  try {
    const parsed = new URL(value);
    return [...new Set([...parsed.searchParams.keys()].filter((key) => SENSITIVE_QUERY_PARAMETER.test(key)))];
  } catch {
    return [];
  }
}

function sanitizedProviderUrl(value: string) {
  const parsed = new URL(value);
  parsed.hash = "";
  for (const key of [...parsed.searchParams.keys()]) {
    if (SENSITIVE_QUERY_PARAMETER.test(key)) parsed.searchParams.delete(key);
  }
  return parsed.href;
}

function externalUrlBlockReason(value: string): string | null {
  if (value.length > MAX_URL_LENGTH) return "The URL is too long to process safely.";
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return "A valid HTTP or HTTPS URL is required.";
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return "Only HTTP and HTTPS URLs are supported.";
  if (parsed.username || parsed.password) return "URLs containing embedded usernames or passwords are not sent to external providers.";
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!hostname || hostname.length > 253) return "The URL hostname is invalid.";
  if (hostname === "localhost" || /\.(?:localhost|local|internal|intranet|home|lan|corp)$/i.test(hostname) || isPrivateOrReservedAddress(hostname)) {
    return "Private, local, and reserved network addresses are not sent to external providers.";
  }
  return null;
}

function normalizedProviderUrl(value: string) {
  const parsed = new URL(value);
  parsed.hash = "";
  return parsed.href;
}

function bytesToBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function statusSigningKey(env: ScannerEnv) {
  const source = env.STATUS_SIGNING_KEY ?? env.VIRUSTOTAL_API_KEY;
  if (!source) return null;
  const material = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`scamshield-status-v1:${source}`));
  return crypto.subtle.importKey("raw", material, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function createStatusToken(analysisId: string, env: ScannerEnv) {
  const key = await statusSigningKey(env);
  if (!key) return null;
  const expires = Math.floor(Date.now() / 1_000) + STATUS_TOKEN_TTL_SECONDS;
  const payload = `${expires}.${analysisId}`;
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return `${expires}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return null;
  }
}

async function verifyStatusToken(analysisId: string, token: string, env: ScannerEnv) {
  const [expiresValue, signatureValue, extra] = token.split(".");
  if (!expiresValue || !signatureValue || extra || token.length > 160) return false;
  const expires = Number(expiresValue);
  const now = Math.floor(Date.now() / 1_000);
  if (!Number.isSafeInteger(expires) || expires < now || expires > now + STATUS_TOKEN_TTL_SECONDS + 60) return false;
  const signature = base64UrlToBytes(signatureValue);
  const key = await statusSigningKey(env);
  if (!signature || !key) return false;
  return crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(`${expires}.${analysisId}`));
}

async function cachedResult<T>(
  namespace: string,
  identifier: string,
  ttlSeconds: number,
  producer: () => Promise<T>,
  ctx?: ScannerContext,
  shouldCache: (result: T) => boolean = () => true,
) {
  const cacheStorage = globalThis.caches as CacheStorage & { default?: Cache };
  const cache = cacheStorage?.default;
  if (!cache) return producer();

  const key = new Request(`https://scamshield-cache.invalid/${namespace}/${await sha256(identifier)}`);
  try {
    const cached = await cache.match(key);
    if (cached) return (await cached.json()) as T;
  } catch {
    // Cache failures should never stop a scan.
  }

  const result = await producer();
  if (!shouldCache(result)) return result;
  const cacheWrite = cache.put(
      key,
      new Response(JSON.stringify(result), {
        headers: {
          "content-type": "application/json",
          "cache-control": `public, max-age=${ttlSeconds}`,
        },
      }),
    ).catch(() => undefined);
  if (ctx) ctx.waitUntil(cacheWrite);
  else await cacheWrite;
  return result;
}

function inspectUrl(url: string) {
  const parsed = new URL(url);
  const domain = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const reasons: string[] = [];
  let score = 8;

  const tld = domain.split(".").pop() ?? "";
  if (suspiciousTlds.has(tld)) {
    score += 18;
    reasons.push(`The .${tld} top-level domain is frequently used in disposable or high-risk campaigns.`);
  }
  if (shorteners.has(domain)) {
    score += 20;
    reasons.push("A link shortener hides the final destination.");
  }
  const isIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain);
  if (isIpAddress) {
    score += 28;
    reasons.push("The link uses a raw IP address instead of a normal domain name.");
  }
  const isPunycode = domain.split(".").some((label) => label.startsWith("xn--"));
  if (isPunycode) {
    score += 25;
    reasons.push("The domain uses Punycode and may imitate another brand with look-alike characters.");
  }
  if (/[A-Z]/.test(parsed.hostname) || /paypa[i1l]|micr[o0]soft|app[l1]e|g[o0]{2}gle/i.test(parsed.hostname)) {
    score += 22;
    reasons.push("The hostname contains a possible brand look-alike or character substitution.");
  }
  const riskyWords = domain.match(/login|verify|secure|account|support|wallet|bonus|claim|update|signin/gi)?.length ?? 0;
  if (riskyWords) {
    score += Math.min(22, riskyWords * 8);
    reasons.push("The domain uses trust or account-related words often seen in phishing links.");
  }
  const hyphens = (domain.match(/-/g) ?? []).length;
  if (hyphens >= 2) {
    score += Math.min(14, hyphens * 4);
    reasons.push("The hostname contains several hyphens, which can be used to mimic a legitimate service.");
  }
  if (domain.length > 42) {
    score += 10;
    reasons.push("The hostname is unusually long.");
  }
  if (parsed.username || parsed.password || url.includes("@")) {
    score += 24;
    reasons.push("The URL contains user-info syntax that can disguise the real destination.");
  }
  if (!reasons.length) reasons.push("No obvious structural red flags were found in the URL itself.");
  return {
    domain,
    score: Math.min(92, score),
    reasons,
    technical: {
      protocol: parsed.protocol === "https:" ? "HTTPS" as const : "HTTP" as const,
      tld,
      usesHttps: parsed.protocol === "https:",
      isIpAddress,
      isPunycode,
      isShortener: shorteners.has(domain),
      hasUserInfo: Boolean(parsed.username || parsed.password || url.includes("@")),
      hostnameLength: domain.length,
      pathDepth: parsed.pathname.split("/").filter(Boolean).length,
      queryParameters: [...parsed.searchParams].length,
    },
  };
}

function unavailableProvider(name: string, detail: string, configured = false): ProviderResult {
  return { name, state: "unavailable", label: configured ? "Unavailable" : "Not configured", detail, configured };
}

async function googleSafeBrowsing(url: string, env: ScannerEnv, ctx?: ScannerContext): Promise<ProviderResult> {
  const apiKey = env.GOOGLE_API_KEY;
  if (!apiKey) {
    return unavailableProvider("Google Safe Browsing", "Add GOOGLE_API_KEY to enable live threat-list checks.");
  }
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return { name: "Google Safe Browsing", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true };
  }

  return cachedResult("gsb-v5", url, 300, async () => {
    try {
      const endpoint = new URL("https://safebrowsing.googleapis.com/v5/urls:search");
      endpoint.searchParams.append("urls", url);
      const response = await fetchWithTimeout(endpoint, {
        headers: {
          accept: "application/json",
          "x-goog-api-key": apiKey,
        },
      });
      if (!response.ok) {
        return unavailableProvider("Google Safe Browsing", `The provider returned HTTP ${response.status}.`, true);
      }
      const data = await readProviderJson(response);
      const flagged = Array.isArray(data?.threats) && data.threats.length > 0;
      return flagged
        ? { name: "Google Safe Browsing", state: "danger", label: "Threat match", detail: "Google Safe Browsing lists this URL as a known threat.", configured: true }
        : { name: "Google Safe Browsing", state: "clear", label: "No match", detail: "No current Google Safe Browsing threat-list match was returned.", configured: true };
    } catch {
      return unavailableProvider("Google Safe Browsing", "The check timed out or could not be reached.", true);
    }
  }, ctx);
}

const commonCountryCodeSecondLevels = new Set(["ac", "co", "com", "edu", "gov", "net", "org"]);

function rdapDomainCandidates(domain: string) {
  const labels = domain.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length <= 2) return [labels.join(".")];

  const countryCodeSuffix = labels.at(-1)?.length === 2 && commonCountryCodeSecondLevels.has(labels.at(-2) ?? "");
  const minimumLabels = countryCodeSuffix ? 3 : 2;
  const firstStart = Math.max(0, labels.length - (minimumLabels + 3));
  const candidates: string[] = [];
  for (let start = firstStart; labels.length - start >= minimumLabels; start += 1) {
    candidates.push(labels.slice(start).join("."));
  }
  return candidates;
}

function safeRdapServiceBase(value: unknown) {
  if (typeof value !== "string") return null;
  try {
    const endpoint = new URL(value);
    if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || externalUrlBlockReason(endpoint.href)) return null;
    endpoint.search = "";
    endpoint.hash = "";
    if (!endpoint.pathname.endsWith("/")) endpoint.pathname += "/";
    return endpoint.href;
  } catch {
    return null;
  }
}

async function rdapServiceUrls(domain: string, ctx?: ScannerContext) {
  const tld = domain.toLowerCase().replace(/\.$/, "").split(".").at(-1) ?? "";
  const discovered: string[] = [];
  try {
    const bootstrap = await cachedResult<Record<string, unknown> | null>(
      "rdap-bootstrap-v1",
      "dns",
      86_400,
      async () => {
        const response = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", {
          headers: { accept: "application/json" },
        }, 3_500);
        if (!response.ok) return null;
        return readProviderJson(response);
      },
      ctx,
      (result) => result !== null,
    );
    const services = Array.isArray(bootstrap?.services) ? bootstrap.services : [];
    for (const entry of services) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      const suffixes = Array.isArray(entry[0]) ? entry[0] : [];
      if (!suffixes.some((suffix) => String(suffix).toLowerCase() === tld)) continue;
      const urls = Array.isArray(entry[1]) ? entry[1] : [];
      for (const value of urls) {
        const service = safeRdapServiceBase(value);
        if (service && !discovered.includes(service)) discovered.push(service);
      }
    }
  } catch {
    // rdap.org remains available as a standards-based bootstrap fallback.
  }
  discovered.push("https://rdap.org/");
  return [...new Set(discovered)];
}

async function rdapDomainAge(domain: string, env: ScannerEnv, ctx?: ScannerContext): Promise<{ provider: ProviderResult; ageDays: number | null; riskBoost: number }> {
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return {
      provider: { name: "RDAP domain age", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true },
      ageDays: 3_650,
      riskBoost: 0,
    };
  }

  return cachedResult("rdap-age-v2", domain, 86_400, async () => {
    try {
      const services = await rdapServiceUrls(domain, ctx);
      const candidates = rdapDomainCandidates(domain);
      let data: Record<string, unknown> | null = null;
      let foundResponse = false;
      const notFoundCandidates = new Set<string>();

      for (const candidate of candidates) {
        for (const service of services) {
          try {
            const endpoint = new URL(`domain/${encodeURIComponent(candidate)}`, service);
            const response = await fetchWithTimeout(endpoint, {
              headers: { accept: "application/rdap+json, application/json" },
              redirect: "follow",
            }, 5_500);
            if (response.status === 404) {
              notFoundCandidates.add(candidate);
              continue;
            }
            if (!response.ok) continue;
            data = await readProviderJson(response);
            if (data) {
              foundResponse = true;
              break;
            }
          } catch {
            // Try another authoritative service or the rdap.org bootstrap fallback.
          }
        }
        if (foundResponse) break;
      }

      if (!foundResponse || !data) {
        if (notFoundCandidates.size !== candidates.length) throw new Error("rdap unavailable");
        return {
          provider: { name: "RDAP domain age", state: "warning", label: "No record", detail: "No public RDAP registration record was found for this domain.", configured: true },
          ageDays: null,
          riskBoost: 16,
        };
      }
      const events = Array.isArray(data?.events) ? data.events : [];
      const registration = events.find((event): event is { eventAction?: string; eventDate?: string } =>
        Boolean(event && typeof event === "object" && /^(?:registration|registered|creation|created)$/i.test(String((event as Record<string, unknown>).eventAction ?? ""))),
      );
      const registrationTime = Date.parse(registration?.eventDate ?? "");
      if (!Number.isFinite(registrationTime) || registrationTime > Date.now() + 86_400_000) {
        return {
          provider: { name: "RDAP domain age", state: "unavailable", label: "Unknown", detail: "The registration record does not publish a creation date.", configured: true },
          ageDays: null,
          riskBoost: 4,
        };
      }
      const ageDays = Math.max(0, Math.floor((Date.now() - registrationTime) / 86_400_000));
      if (ageDays < 30) {
        return {
          provider: { name: "RDAP domain age", state: "warning", label: "Very new", detail: `The domain was registered about ${ageDays} day${ageDays === 1 ? "" : "s"} ago.`, configured: true },
          ageDays,
          riskBoost: 24,
        };
      }
      if (ageDays < 180) {
        return {
          provider: { name: "RDAP domain age", state: "warning", label: "New domain", detail: `The domain is about ${ageDays} days old.`, configured: true },
          ageDays,
          riskBoost: 12,
        };
      }
      return {
        provider: { name: "RDAP domain age", state: "clear", label: "Established", detail: `The domain is about ${ageDays} days old. Age alone does not prove safety.`, configured: true },
        ageDays,
        riskBoost: 0,
      };
    } catch {
      return { provider: unavailableProvider("RDAP domain age", "The registration lookup timed out or was unavailable.", true), ageDays: null, riskBoost: 0 };
    }
  }, ctx, (result) => result.provider.label !== "Unavailable");
}

function base64Url(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function vtVerdict(stats: Record<string, number> | null) {
  const malicious = stats?.malicious ?? 0;
  const suspicious = stats?.suspicious ?? 0;
  if (malicious > 0) return { state: "danger" as const, label: `${malicious} malicious`, boost: 94 };
  if (suspicious > 0) return { state: "warning" as const, label: `${suspicious} suspicious`, boost: 72 };
  return { state: "clear" as const, label: "No detections", boost: 0 };
}

async function virusTotalExisting(url: string, env: ScannerEnv, ctx?: ScannerContext): Promise<{ provider: ProviderResult; report: LinkReport["virusTotal"]; riskBoost: number }> {
  if (!env.VIRUSTOTAL_API_KEY) {
    return { provider: unavailableProvider("VirusTotal", "Add VIRUSTOTAL_API_KEY to enable reputation and fresh-analysis checks."), report: null, riskBoost: 0 };
  }
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return {
      provider: { name: "VirusTotal", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true },
      report: { found: false, stats: null, lastAnalysisDate: null },
      riskBoost: 0,
    };
  }

  return cachedResult("vt-existing", url, 180, async () => {
    try {
      const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${base64Url(url)}`, {
        headers: { "x-apikey": env.VIRUSTOTAL_API_KEY ?? "", accept: "application/json" },
      });
      if (response.status === 404) {
        return {
          provider: { name: "VirusTotal", state: "not-run", label: "No report", detail: "VirusTotal has no existing report for this exact URL. A new analysis requires your consent.", configured: true },
          report: { found: false, stats: null, lastAnalysisDate: null },
          riskBoost: 0,
        };
      }
      if (!response.ok) {
        return { provider: unavailableProvider("VirusTotal", `The provider returned HTTP ${response.status}.`, true), report: null, riskBoost: 0 };
      }
      const data = await readProviderJson(response) as {
        data?: { attributes?: { last_analysis_stats?: Record<string, number>; last_analysis_date?: number } };
      } | null;
      const stats = data?.data?.attributes?.last_analysis_stats ?? null;
      const lastAnalysisDate = data?.data?.attributes?.last_analysis_date ?? null;
      const verdict = vtVerdict(stats);
      const engines = stats ? Object.values(stats).reduce((sum, count) => sum + count, 0) : 0;
      return {
        provider: {
          name: "VirusTotal",
          state: verdict.state,
          label: verdict.label,
          detail: stats
            ? `Existing report: ${stats.malicious ?? 0} malicious, ${stats.suspicious ?? 0} suspicious, ${stats.harmless ?? 0} harmless, and ${stats.undetected ?? 0} undetected verdicts across ${engines} engines.`
            : "An existing object was found, but it contains no current engine summary.",
          configured: true,
        },
        report: { found: true, stats, lastAnalysisDate },
        riskBoost: verdict.boost,
      };
    } catch {
      return { provider: unavailableProvider("VirusTotal", "The existing-report check timed out or was unavailable.", true), report: null, riskBoost: 0 };
    }
  }, ctx);
}

async function analyzeLink(
  url: string,
  mode: "quick" | "deep",
  env: ScannerEnv,
  allowSensitiveUrlSharing: boolean,
  ctx?: ScannerContext,
): Promise<LinkReport> {
  const originalUrl = normalizedProviderUrl(url);
  const sensitiveParameters = sensitiveQueryParameters(originalUrl);
  const shareFullUrl = sensitiveParameters.length === 0 || allowSensitiveUrlSharing;
  const providerUrl = shareFullUrl ? originalUrl : sanitizedProviderUrl(originalUrl);
  const sharingMode = sensitiveParameters.length === 0
    ? "standard" as const
    : shareFullUrl ? "full-with-consent" as const : "sanitized" as const;
  const externalSharing = { mode: sharingMode, sensitiveParameters, providerUrl };
  const privacyDetail = sharingMode === "sanitized"
    ? ` Sensitive query values (${sensitiveParameters.join(", ")}) were removed before this external check.`
    : sharingMode === "full-with-consent"
      ? " The complete URL was checked because explicit sensitive-URL sharing consent was provided."
      : "";
  const structural = inspectUrl(originalUrl);
  const externalBlock = externalUrlBlockReason(providerUrl);
  if (externalBlock) {
    const domainIntel = await analyzeDomainIntelligence(providerUrl, mode, {
      externalDisabled: isEnabled(env.DISABLE_EXTERNAL_CHECKS),
      protectedReason: externalBlock,
      ctx,
    });
    return {
      url: originalUrl,
      domain: structural.domain,
      riskScore: Math.min(99, Math.max(structural.score, 34)),
      reasons: [externalBlock, ...structural.reasons].slice(0, 7),
      providers: [
        { name: "Google Safe Browsing", state: "not-run", label: "Protected", detail: externalBlock, configured: Boolean(env.GOOGLE_API_KEY) },
        { name: "RDAP domain age", state: "not-run", label: "Protected", detail: externalBlock, configured: true },
        { name: "VirusTotal", state: "not-run", label: "Protected", detail: externalBlock, configured: Boolean(env.VIRUSTOTAL_API_KEY) },
        ...domainIntel.providers,
      ],
      domainAgeDays: null,
      virusTotal: null,
      externalSharing,
      domainIntelligence: domainIntel.intelligence,
      technical: structural.technical,
    };
  }
  const [google, rdap, vt, domainIntel] = await Promise.all([
    googleSafeBrowsing(providerUrl, env, ctx),
    rdapDomainAge(structural.domain, env, ctx),
    mode === "deep"
      ? virusTotalExisting(providerUrl, env, ctx)
      : Promise.resolve({
          provider: { name: "VirusTotal", state: "not-run" as const, label: "Deep Scan only", detail: "Run Deep Scan to check the latest existing VirusTotal report.", configured: Boolean(env.VIRUSTOTAL_API_KEY) },
          report: null,
          riskBoost: 0,
        }),
    analyzeDomainIntelligence(providerUrl, mode, {
      externalDisabled: isEnabled(env.DISABLE_EXTERNAL_CHECKS),
      ctx,
    }),
  ]);

  let riskScore = structural.score + rdap.riskBoost + domainIntel.riskBoost;
  if (google.state === "danger") riskScore = Math.max(riskScore, 94);
  riskScore = Math.max(riskScore, vt.riskBoost);
  riskScore = Math.max(riskScore, domainIntel.riskFloor);
  const reasons = [...structural.reasons];
  if (google.state === "danger") reasons.unshift("Google Safe Browsing returned a known-threat match.");
  if (rdap.riskBoost >= 12) reasons.push(rdap.provider.detail);
  if (vt.riskBoost >= 72) reasons.unshift(vt.provider.detail);
  reasons.unshift(...domainIntel.reasons);

  return {
    url: originalUrl,
    domain: structural.domain,
    riskScore: Math.min(99, riskScore),
    reasons: reasons.slice(0, 7),
    providers: [google, rdap.provider, vt.provider, ...domainIntel.providers]
      .map((provider) => privacyDetail && ["Google Safe Browsing", "VirusTotal", "Redirect path"].includes(provider.name)
        ? { ...provider, detail: `${provider.detail}${privacyDetail}` }
        : provider),
    domainAgeDays: rdap.ageDays,
    virusTotal: vt.report,
    externalSharing,
    domainIntelligence: domainIntel.intelligence,
    technical: structural.technical,
  };
}

function riskLevel(score: number): RiskLevel {
  if (score >= 67) return "High";
  if (score >= 34) return "Medium";
  return "Low";
}

function recommendedActions(level: RiskLevel) {
  if (level === "High") {
    return [
      "Do not click links, reply, pay, or share login codes.",
      "Verify the request through an official app, saved bookmark, or independently found phone number.",
      "Report the message to the platform, your organization, or the relevant national cybercrime channel.",
    ];
  }
  if (level === "Medium") {
    return [
      "Pause before interacting with the sender or link.",
      "Confirm the request through a separate, trusted communication channel.",
      "Avoid sharing credentials, identity documents, payment details, or verification codes.",
    ];
  }
  return [
    "Use the service through its official app or a saved bookmark when possible.",
    "Stay cautious if the sender later introduces urgency, payment, or credential requests.",
    "Treat this result as guidance, not a guarantee of safety.",
  ];
}

function extractIocs(message: string, urls: string[]) {
  const domains = [...new Set(urls.map((url) => new URL(url).hostname.toLowerCase()))];
  const emails = [...new Set(message.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi) ?? [])];
  const phones = [...new Set(message.match(/\+?\d[\d\s().-]{7,}\d/g) ?? [])].slice(0, 8);
  const cryptoWallets = [...new Set(message.match(/\b(?:bc1[a-z0-9]{25,62}|0x[a-f0-9]{40})\b/gi) ?? [])];
  return { urls, domains, emails, phones, cryptoWallets };
}

async function runScan(
  message: string,
  mode: "quick" | "deep",
  env: ScannerEnv,
  allowSensitiveUrlSharing: boolean,
  ctx?: ScannerContext,
) {
  const scanStartedAt = performance.now();
  const urls = extractUrls(message);
  const local = messageAnalysis(message, urls);
  const localAnalysisMs = Math.round(performance.now() - scanStartedAt);
  const liveChecksStartedAt = performance.now();
  const links = await Promise.all(urls.map((url) => analyzeLink(url, mode, env, allowSensitiveUrlSharing, ctx)));
  const liveChecksMs = Math.round(performance.now() - liveChecksStartedAt);

  const maxLinkRisk = links.reduce((max, link) => Math.max(max, link.riskScore), 0);
  const blendedRisk = Math.round(local.score * (links.length ? 0.64 : 1) + maxLinkRisk * (links.length ? 0.36 : 0));
  let riskPercent = Math.max(local.score, maxLinkRisk, blendedRisk);
  if (links.length && local.indicators.urgency > 0 && local.indicators.credentials > 0) {
    riskPercent = Math.max(riskPercent, 76);
  } else if (links.length && local.indicators.credentials > 0 && maxLinkRisk >= 34) {
    riskPercent = Math.max(riskPercent, 68);
  }
  if (links.some((link) => link.providers.some((provider) => provider.state === "danger"))) {
    riskPercent = Math.max(riskPercent, 90);
  }
  riskPercent = Math.min(99, riskPercent);
  const level = riskLevel(riskPercent);

  const providerThreatReasons = links.flatMap((link) =>
    link.reasons.filter((reason) => /Google Safe Browsing|VirusTotal/i.test(reason)),
  );
  const structuralReasons = links.flatMap((link) =>
    link.reasons.filter((reason) => !/No obvious structural|Google Safe Browsing|VirusTotal/i.test(reason)),
  );
  const combinedReasons = [...providerThreatReasons, ...local.reasons, ...structuralReasons];
  const reasons = [...new Set(combinedReasons)].slice(0, 6);
  while (reasons.length < 3) {
    reasons.push(
      reasons.length === 1
        ? "No live reputation provider returned a confirmed threat match."
        : "A clean result cannot prove that a sender or link is trustworthy.",
    );
  }

  const providers = links.length
    ? links.flatMap((link) => link.providers.map((provider) => ({ ...provider, subject: link.domain })))
    : [
        { name: "Google Safe Browsing", state: "not-run", label: "No URL", detail: "No URL was found in the supplied text.", configured: Boolean(env.GOOGLE_API_KEY), subject: "Message only" },
        { name: "RDAP domain age", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        {
          name: "VirusTotal",
          state: "not-run",
          label: "No URL",
          detail: "VirusTotal analyzes URLs, and this input contains no link.",
          configured: Boolean(env.VIRUSTOTAL_API_KEY),
          subject: "Message only",
        },
        { name: "Brand similarity", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        { name: "DNS footprint", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        { name: "Certificate Transparency", state: "not-run", label: "No domain", detail: "No domain was found in the supplied text.", configured: true, subject: "Message only" },
        { name: "Redirect path", state: "not-run", label: "No URL", detail: "No URL was found in the supplied text.", configured: true, subject: "Message only" },
      ];

  const providerCoverage = {
    total: providers.length,
    completed: providers.filter((provider) => ["clear", "warning", "danger"].includes(provider.state)).length,
    threats: providers.filter((provider) => provider.state === "danger").length,
    warnings: providers.filter((provider) => provider.state === "warning").length,
    unavailable: providers.filter((provider) => provider.state === "unavailable").length,
    notRun: providers.filter((provider) => provider.state === "not-run").length,
  };
  const messageWithoutUrls = urls.reduce((value, url) => value.replace(url, ""), message).trim();

  return {
    scanMode: mode,
    scannedAt: new Date().toISOString(),
    riskPercent,
    riskLevel: level,
    riskLabel: level === "High" ? "Likely dangerous" : level === "Medium" ? "Needs verification" : "No strong threat found",
    scamType: local.scamType,
    reasons,
    actions: recommendedActions(level),
    evidence: [
      ...local.reasons.map((detail, index) => ({ source: "Message", impact: index === 0 && local.score >= 50 ? "High" : "Medium", detail })),
      ...links.flatMap((link) => link.reasons.map((detail) => ({ source: link.domain, impact: link.riskScore >= 67 ? "High" : link.riskScore >= 34 ? "Medium" : "Low", detail }))),
    ].slice(0, 18),
    links,
    providers,
    iocs: extractIocs(message, urls),
    privacy: {
      sensitiveUrlDetected: links.some((link) => link.externalSharing.sensitiveParameters.length > 0),
      fullSensitiveUrlsShared: links.filter((link) => link.externalSharing.mode === "full-with-consent").length,
      sanitizedUrls: links.filter((link) => link.externalSharing.mode === "sanitized").length,
    },
    analysis: {
      inputType: urls.length === 0 ? "Message" : messageWithoutUrls.length < 8 ? "URL" : "Message + URL",
      rulesEvaluated:
        categoryRules.reduce((sum, rule) => sum + rule.patterns.length, 0) +
        urgencyPatterns.length +
        credentialPatterns.length +
        credentialRequestPatterns.length +
        paymentPatterns.length +
        consequencePatterns.length +
        rewardPatterns.length +
        callToActionPatterns.length +
        impersonationPatterns.length +
        secrecyPatterns.length +
        authorityPatterns.length +
        evasionPatterns.length +
        benignContextPatterns.length +
        routineAccountNoticePatterns.length,
      messageStats: local.stats,
      detectedLanguage: local.detectedLanguage,
      signals: local.signals,
      categoryMatches: local.categories,
      context: local.context,
      model: local.model,
      providerCoverage,
      timing: {
        localAnalysisMs,
        liveChecksMs,
        totalMs: Math.round(performance.now() - scanStartedAt),
      },
    },
    deepScan: {
      checkedExistingReport: mode === "deep" && urls.length > 0,
      canSubmitFreshAnalysis: mode === "deep" && urls.length > 0 && Boolean(env.VIRUSTOTAL_API_KEY),
      urls,
      privacyNotice:
        "Submitting starts a new VirusTotal analysis. The URL and resulting report may be shared with VirusTotal and its security community. Sensitive URL values stay protected unless you separately consent to exact URL sharing.",
      timingNotice:
        "A fresh VirusTotal scan runs on VirusTotal infrastructure. Queue and engine response time can vary; ScamShield will keep its own result visible while tracking the external analysis.",
    },
    limits: { maxUrls: MAX_URLS, truncatedUrls: (message.match(/https?:\/\//gi)?.length ?? 0) > MAX_URLS },
  };
}

async function handleScan(request: Request, env: ScannerEnv, ctx?: ScannerContext) {
  const parsedBody = await parseJsonObject(request, MAX_SCAN_BODY_BYTES);
  if (parsedBody.response) return parsedBody.response;
  const body = parsedBody.body ?? {};

  const message = cleanMessage(body.message);
  const mode = body.mode === "deep" ? "deep" : "quick";
  if (!message) return jsonResponse({ error: "Paste a message or link before starting a scan." }, 400);
  if (message.length > MAX_MESSAGE_LENGTH) {
    return jsonResponse({ error: `Input is too long. The maximum is ${MAX_MESSAGE_LENGTH.toLocaleString()} characters.` }, 413);
  }

  const limit = mode === "deep" ? 5 : 20;
  let rate;
  try {
    rate = await checkRateLimit(request, env, mode, limit, 60);
  } catch (error) {
    console.error(JSON.stringify({
      event: "rate_limit_failed",
      action: mode,
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return rateLimitUnavailable();
  }
  if (!rate.allowed) {
    return jsonResponse(
      { error: `Too many ${mode} scans. Try again in ${rate.retryAfter} seconds.` },
      429,
      { ...rateLimitHeaders(rate), "retry-after": String(rate.retryAfter) },
    );
  }

  const verification = await validateTurnstile(request, env, body.turnstileToken);
  if (verification.misconfigured) {
    return jsonResponse({ error: "Human verification is temporarily unavailable." }, 503);
  }
  if (!verification.valid) {
    return jsonResponse({ error: "Human verification failed or expired. Please complete it again.", verificationRequired: true }, 403);
  }

  const result = await runScan(message, mode, env, body.sensitiveUrlConsent === true, ctx);
  return jsonResponse(result, 200, rateLimitHeaders(rate));
}

async function handleDiagnostics(request: Request, env: ScannerEnv) {
  const parsedBody = await parseJsonObject(request, MAX_DIAGNOSTICS_BODY_BYTES);
  if (parsedBody.response) return parsedBody.response;
  const event = sanitizeDiagnosticPayload(parsedBody.body);
  if (!event) {
    return jsonResponse({ error: "Invalid anonymous diagnostic event." }, 400);
  }

  let rate;
  try {
    rate = await checkRateLimit(request, env, "diagnostics", 60, 60 * 60);
  } catch (error) {
    console.error(JSON.stringify({
      event: "rate_limit_failed",
      action: "diagnostics",
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return rateLimitUnavailable();
  }
  if (!rate.allowed) {
    return jsonResponse(
      { error: "Anonymous diagnostics limit reached. Try again later." },
      429,
      { ...rateLimitHeaders(rate), "retry-after": String(rate.retryAfter) },
    );
  }

  try {
    if (!writeDiagnostic(env, event)) {
      return jsonResponse({ error: "Anonymous diagnostics are not configured." }, 503);
    }
    return jsonResponse({ recorded: true }, 202, rateLimitHeaders(rate));
  } catch (error) {
    console.error(JSON.stringify({
      event: "diagnostic_write_failed",
      diagnosticType: event.event,
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return jsonResponse({ error: "Anonymous diagnostics are temporarily unavailable." }, 503);
  }
}

async function handleDeepSubmit(request: Request, env: ScannerEnv) {
  const parsedBody = await parseJsonObject(request, MAX_DEEP_BODY_BYTES);
  if (parsedBody.response) return parsedBody.response;
  const body = parsedBody.body ?? {};
  if (body.consent !== true) return jsonResponse({ error: "Explicit consent is required before sending a URL to VirusTotal." }, 400);
  if (!env.VIRUSTOTAL_API_KEY) return jsonResponse({ error: "Fresh VirusTotal analysis is not configured on this deployment." }, 503);

  const urlValue = typeof body.url === "string" ? body.url.trim() : "";
  const sensitiveParameters = sensitiveQueryParameters(urlValue);
  if (sensitiveParameters.length > 0 && body.sensitiveUrlConsent !== true) {
    return jsonResponse({
      error: "This URL contains a sensitive access token or credential. Explicit sensitive-URL sharing consent is required.",
      sensitiveUrlConsentRequired: true,
    }, 400);
  }
  const urlBlock = externalUrlBlockReason(urlValue);
  if (urlBlock) return jsonResponse({ error: urlBlock }, 400);
  const parsed = new URL(normalizedProviderUrl(urlValue));

  let rate;
  try {
    rate = await checkRateLimit(request, env, "deep-submit", 2, 600);
  } catch (error) {
    console.error(JSON.stringify({
      event: "rate_limit_failed",
      action: "deep-submit",
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return rateLimitUnavailable();
  }
  if (!rate.allowed) {
    return jsonResponse(
      { error: `Fresh analysis limit reached. Try again in ${rate.retryAfter} seconds.` },
      429,
      { ...rateLimitHeaders(rate), "retry-after": String(rate.retryAfter) },
    );
  }

  const verification = await validateTurnstile(request, env, body.turnstileToken);
  if (verification.misconfigured) {
    return jsonResponse({ error: "Human verification is temporarily unavailable." }, 503);
  }
  if (!verification.valid) {
    return jsonResponse({ error: "Human verification failed or expired. Please complete it again.", verificationRequired: true }, 403);
  }

  try {
    const form = new URLSearchParams({ url: parsed.href });
    const response = await fetchWithTimeout(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "x-apikey": env.VIRUSTOTAL_API_KEY,
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: form.toString(),
      },
      8_000,
    );
    const data = await readProviderJson(response) as { data?: { id?: string } } | null;
    if (!response.ok || !data?.data?.id) {
      return jsonResponse({ error: response.status === 429 ? "VirusTotal rate limit reached. Try again later." : "VirusTotal did not accept the analysis request." }, response.status === 429 ? 429 : 502);
    }
    const statusToken = await createStatusToken(data.data.id, env);
    if (!statusToken) return jsonResponse({ error: "Secure analysis tracking could not be initialized." }, 500);
    return jsonResponse({
      analysisId: data.data.id,
      statusToken,
      status: "queued",
      url: parsed.href,
      message: "VirusTotal accepted the URL. ScamShield will now track the analysis until it finishes.",
      pollAfterMs: 750,
    });
  } catch {
    return jsonResponse({ error: "VirusTotal could not be reached or the request timed out." }, 502);
  }
}

async function handleDeepStatus(request: Request, env: ScannerEnv) {
  if (!env.VIRUSTOTAL_API_KEY) return jsonResponse({ error: "VirusTotal is not configured." }, 503);
  const requestUrl = new URL(request.url);
  const analysisId = requestUrl.searchParams.get("id")?.trim() ?? "";
  if (!/^[-\w]+$/.test(analysisId) || analysisId.length > 200) return jsonResponse({ error: "Invalid analysis ID." }, 400);
  const statusToken = request.headers.get("x-scamshield-status-token")?.trim() ?? "";
  if (!await verifyStatusToken(analysisId, statusToken, env)) {
    return jsonResponse({ error: "This analysis tracking token is invalid or expired." }, 403);
  }

  let rate;
  try {
    rate = await checkRateLimit(request, env, "deep-status", 30, 60);
  } catch (error) {
    console.error(JSON.stringify({
      event: "rate_limit_failed",
      action: "deep-status",
      errorType: error instanceof Error ? error.name : "UnknownError",
    }));
    return rateLimitUnavailable();
  }
  if (!rate.allowed) {
    return jsonResponse(
      { error: "Polling too quickly. Wait a moment and try again." },
      429,
      { ...rateLimitHeaders(rate), "retry-after": String(rate.retryAfter) },
    );
  }

  try {
    const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { "x-apikey": env.VIRUSTOTAL_API_KEY, accept: "application/json" },
    });
    const data = await readProviderJson(response) as {
      data?: { attributes?: { status?: string; stats?: Record<string, number>; date?: number } };
    } | null;
    if (!response.ok) return jsonResponse({ error: response.status === 429 ? "VirusTotal rate limit reached. Try again later." : "Analysis status is temporarily unavailable." }, response.status === 429 ? 429 : 502);
    const attributes = data?.data?.attributes ?? {};
    const status = attributes.status ?? "queued";
    const stats = attributes.stats ?? null;
    const verdict = vtVerdict(stats);
    const engineCount = stats ? Object.values(stats).reduce((sum, count) => sum + count, 0) : 0;
    return jsonResponse({
      status,
      completed: status === "completed",
      stats,
      verdict: status === "completed" ? verdict.label : null,
      riskState: status === "completed" ? verdict.state : "pending",
      analyzedAt: attributes.date ?? null,
      engineCount,
      pollAfterMs: status === "completed" ? 0 : status === "queued" ? 1_500 : 1_000,
    });
  } catch {
    return jsonResponse({ error: "Analysis status could not be retrieved." }, 502);
  }
}

export async function handleScannerApi(request: Request, env: ScannerEnv, ctx?: ScannerContext): Promise<Response | null> {
  const url = new URL(request.url);

  if (url.pathname === "/health" && request.method === "GET") {
    return jsonResponse({ status: "ok" });
  }
  if (url.pathname === "/api/config" && request.method === "GET") {
    return jsonResponse({
      turnstileSiteKey: env.TURNSTILE_SITE_KEY ?? null,
      turnstileConfigured: Boolean(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY),
    });
  }
  const methods: Record<string, "GET" | "POST"> = {
    "/health": "GET",
    "/api/config": "GET",
    "/api/scan": "POST",
    "/api/diagnostics": "POST",
    "/api/deep/submit": "POST",
    "/api/deep/status": "GET",
  };
  const allowedMethod = methods[url.pathname];
  if (allowedMethod && request.method !== allowedMethod) {
    return jsonResponse({ error: "Method not allowed." }, 405, { allow: allowedMethod });
  }
  if ((url.pathname === "/api/scan" || url.pathname === "/api/diagnostics" || url.pathname === "/api/deep/submit") && !isTrustedWriteRequest(request)) {
    return jsonResponse({ error: "Cross-site requests are not allowed." }, 403);
  }
  if (url.pathname === "/api/scan") return handleScan(request, env, ctx);
  if (url.pathname === "/api/diagnostics") return handleDiagnostics(request, env);
  if (url.pathname === "/api/deep/submit") return handleDeepSubmit(request, env);
  if (url.pathname === "/api/deep/status") return handleDeepStatus(request, env);
  if (url.pathname.startsWith("/api/") || url.pathname === "/health") {
    return jsonResponse({ error: "Not found." }, 404);
  }
  return null;
}
