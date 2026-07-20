export interface ScannerEnv {
  GOOGLE_API_KEY?: string;
  VIRUSTOTAL_API_KEY?: string;
  STATUS_SIGNING_KEY?: string;
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

interface Rule {
  type: string;
  patterns: RegExp[];
  weight: number;
}

const MAX_MESSAGE_LENGTH = 10_000;
const MAX_URLS = 3;
const MAX_URL_LENGTH = 2_048;
const MAX_SCAN_BODY_BYTES = 48 * 1_024;
const MAX_DEEP_BODY_BYTES = 8 * 1_024;
const REQUEST_TIMEOUT_MS = 4_500;
const PROVIDER_JSON_LIMIT_BYTES = 256 * 1_024;
const STATUS_TOKEN_TTL_SECONDS = 30 * 60;
const TURNSTILE_ACTION = "turnstile-spin-v2";
const rateBuckets = new Map<string, number[]>();

const categoryRules: Rule[] = [
  {
    type: "Brand impersonation / fake charge",
    weight: 16,
    patterns: [
      /(?:apple|paypal|zelle|microsoft|amazon|netflix|icloud|google|bank|fedex|ups|dhl).{0,100}(?:account|payment|bill|charged|paid|support|transaction)/i,
      /(?:bill|payment|transaction|purchase).{0,80}(?:\$\s?\d+|usd|declined|unauthori[sz]ed|dispute)/i,
      /dispute.{0,30}(?:call|contact).{0,20}\d{7,}/i,
      /if you did not.{0,80}(?:call|click|change|contact)/i,
      /(?:nalog|racun).{0,80}(?:naplacen|placen|transakcij|neovlasten)/i,
    ],
  },
  {
    type: "Account takeover / phishing",
    weight: 15,
    patterns: [
      /(?:verify|confirm|validate|update|restore|unlock|secure).{0,50}(?:account|identity|login|password|payment information|details)/i,
      /(?:account|cloud|storage|subscription).{0,90}(?:suspend|deactivat|locked|frozen|deleted|expire|full|on hold)/i,
      /(?:payment method|credit card|debit card).{0,50}(?:declined|failed|expired|update)/i,
      /(?:action required|update payment information|sign in here)/i,
      /(?:unusual|suspicious).{0,35}(?:login|activity|transaction)/i,
      /password.{0,30}(?:expire|reset|change|confirm)/i,
      /(?:nalog|racun).{0,60}(?:blokiran|zakljucan|zamrznut|deaktiviran)/i,
      /potvrd(?:i|ite).{0,30}(?:nalog|identitet|lozink|uplatu)/i,
    ],
  },
  {
    type: "Delivery / postal scam",
    weight: 13,
    patterns: [
      /(?:parcel|package|delivery|shipment|fedex|ups|dhl|usps).{0,120}(?:fee|address|failed|held|customs|reschedule|total due|payment|creditcard)/i,
      /(?:paket|posiljka|dostava).{0,100}(?:naknad|adres|zadrzan|carin|neuspjel|uplati)/i,
      /(?:shipping|handling|insurance).{0,80}(?:fee|\$\s?\d+|total due)/i,
      /customs.{0,25}(?:fee|charge|payment)/i,
    ],
  },
  {
    type: "Investment / crypto scam",
    weight: 15,
    patterns: [
      /(?:crypto|bitcoin|btc|usdt|forex|trading).{0,100}(?:guaranteed|profit|return|signal|deposit|withdraw|bonus|casino)/i,
      /(?:withdrawal|payout).{0,100}(?:deposit|fee|tax|unlock|frozen|review)/i,
      /pay.{0,40}(?:\d+%|deposit).{0,100}(?:withdraw|release|receive)/i,
      /(?:double|multiply).{0,20}(?:money|crypto|investment)/i,
      /(?:signal prediction|buy \d+%|trading signal)/i,
      /wallet.{0,35}(?:validation|synchronization|unlock|connect)/i,
      /sigurn(?:a|i).{0,25}(?:zarada|profit|povrat)/i,
    ],
  },
  {
    type: "Prize / advance-fee scam",
    weight: 14,
    patterns: [
      /(?:won|winner|prize|lottery|giveaway|reward|bonus).{0,120}(?:claim|register|withdraw|fee|promo code|pay|instantly)/i,
      /(?:osvojili|dobitnik|nagrada|poklon|bonus).{0,100}(?:preuzm|registr|naknad|uplati|kod)/i,
      /(?:mrbeast|celebrity|influencer).{0,100}(?:giveaway|bonus|crypto|casino)/i,
      /(?:processing|release|administration).{0,20}fee/i,
      /(?:inheritance|grant).{0,80}(?:fee|transfer|release)/i,
    ],
  },
  {
    type: "Job scam",
    weight: 12,
    patterns: [
      /(?:remote|data entry|work from home|online).{0,120}(?:position|job|interview|hourly rate|earn|training)/i,
      /(?:job|position|application|resume|creator).{0,150}(?:reply ["']?yes|onboard|interview|bonus|\$\s?\d+|meeting)/i,
      /(?:onboarding|recruiting).{0,120}(?:creators?|candidate|platform|remote|bonus|joining)/i,
      /(?:posao od kuce|udaljeni posao).{0,100}(?:zarad|dnevno|sedmicno|obuk|intervju)/i,
      /pay.{0,80}(?:training|equipment).{0,100}(?:job|position)/i,
    ],
  },
  {
    type: "Tech support scam",
    weight: 14,
    patterns: [
      /(?:computer|device).*(?:infected|virus|compromised)/i,
      /(?:računar|uređaj).*(?:zaražen|virus|hakovan)/i,
      /call (?:microsoft|support).*(?:immediately|now)/i,
    ],
  },
  {
    type: "Marketplace / payment scam",
    weight: 15,
    patterns: [
      /(?:zelle|paypal|cash app|venmo).{0,100}(?:paid you|account on hold|business account|credit your funds|above your limit)/i,
      /(?:account on hold|unable to credit|upgrade.{0,30}business).{0,100}(?:pay|refund|send|funds)/i,
      /(?:pay half|deposit).{0,80}(?:take.{0,30}(?:post|listing).{0,20}down|mark.{0,15}sold)/i,
      /(?:apple|google|steam|amazon).{0,20}gift card/i,
      /(?:pre-owned|used item).{0,100}(?:visit|online store|pay|shipping)/i,
    ],
  },
  {
    type: "Document / SMS phishing",
    weight: 13,
    patterns: [
      /(?:document|invoice|voicemail|review|notice).{0,80}(?:awaiting|pending|access|open|view)/i,
      /(?:periodic review|no action required).{0,120}(?:https?:\/\/|www\.|reply stop)/i,
      /(?:reply stop|opt[- ]out).{0,120}(?:https?:\/\/|www\.)/i,
      /(?:access|open|view).{0,30}(?:document|invoice|message).{0,50}(?:here|link)/i,
    ],
  },
  {
    type: "Romance / impersonation scam",
    weight: 11,
    patterns: [
      /(?:deployed|offshore|abroad).*(?:money|gift card|transfer)/i,
      /(?:hitno|urgentno).*(?:pošalji|uplati).*(?:novac|kartic)/i,
      /pretend(?:ing)? to be/i,
    ],
  },
];

const urgencyPatterns = [
  /urgent(?:ly)?/i,
  /immediately/i,
  /within (?:\d+ )?(?:minutes?|hours?)/i,
  /act now/i,
  /hitno/i,
  /odmah/i,
  /u roku od/i,
  /zadnja opomena/i,
  /within \d+ days?/i,
  /within \d+ hours?/i,
  /today/i,
  /right now/i,
  /\bnow\b/i,
  /don['’]t miss/i,
  /last chance/i,
  /will be (?:deleted|frozen|suspended|closed)/i,
];

const credentialPatterns = [
  /password/i,
  /passcode/i,
  /verification code/i,
  /one[- ]time code/i,
  /login/i,
  /lozink/i,
  /kod za potvrdu/i,
  /prijav/i,
  /bank details/i,
  /payment information/i,
  /card (?:number|details|information)/i,
  /security (?:code|question)/i,
  /social security/i,
];

const paymentPatterns = [
  /gift card/i,
  /wire transfer/i,
  /bank transfer/i,
  /crypto(?:currency)?/i,
  /bitcoin/i,
  /uplati/i,
  /novac/i,
  /naknad/i,
  /kartic/i,
  /\busd\b/i,
  /\busdt\b/i,
  /total due/i,
  /deposit/i,
  /payment method/i,
  /withdrawal/i,
  /hourly rate/i,
];

const consequencePatterns = [
  /suspend(?:ed|ing|sion)?/i,
  /deactivat(?:e|ed|ion)/i,
  /locked/i,
  /frozen/i,
  /deleted/i,
  /account on hold/i,
  /unable to credit/i,
  /payment.{0,25}(?:failed|declined)/i,
  /data.{0,30}(?:lost|deleted|removed)/i,
  /(?:blokiran|zakljucan|zamrznut|obrisan)/i,
];

const rewardPatterns = [
  /\bbonus\b/i,
  /giveaway/i,
  /\bprize\b/i,
  /\breward\b/i,
  /guaranteed.{0,20}(?:profit|return|income)/i,
  /earn.{0,20}(?:daily|weekly|per day|\$\s?\d+)/i,
  /paid you/i,
  /receive.{0,20}\$\s?\d+/i,
  /(?:nagrada|poklon|zarad)/i,
];

const callToActionPatterns = [
  /(?:click|visit|access|open|view).{0,30}(?:here|link|site|page|document)/i,
  /(?:update|confirm|verify|enter|submit).{0,35}(?:details|information|account|payment|password|code)/i,
  /(?:reply|respond).{0,25}(?:yes|stop|confirm|link)/i,
  /(?:call|contact|text).{0,25}\d{7,}/i,
  /(?:register|sign up|schedule|book).{0,35}(?:now|here|meeting|account)/i,
  /(?:pay|send|transfer|buy).{0,40}(?:fee|deposit|gift card|crypto|money|half|\$\s?\d+)/i,
];

const impersonationPatterns = [
  /(?:apple|paypal|zelle|microsoft|amazon|netflix|icloud|google|fedex|ups|dhl) (?:account|support|team|payment|security)/i,
  /(?:hiring|recruiting|support|security|billing) (?:department|team)/i,
  /sincerely.{0,30}(?:support|security|billing)/i,
  /copyright.{0,50}(?:apple|microsoft|google|amazon)/i,
];

const suspiciousTlds = new Set([
  "zip",
  "mov",
  "click",
  "top",
  "xyz",
  "live",
  "support",
  "work",
  "shop",
  "rest",
  "gq",
  "tk",
]);

const shorteners = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
]);

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
  return (
    request.headers.get("CF-Connecting-IP") ??
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ??
    "local"
  );
}

async function getRateKey(request: Request, action: string) {
  return `${await sha256(getClientIp(request))}:${action}`;
}

function checkRateLimit(key: string, limit: number, windowSeconds: number) {
  const now = Date.now();
  const cutoff = now - windowSeconds * 1_000;
  const current = (rateBuckets.get(key) ?? []).filter((timestamp) => timestamp > cutoff);
  if (current.length >= limit) {
    const retryAfter = Math.max(1, Math.ceil((current[0] + windowSeconds * 1_000 - now) / 1_000));
    rateBuckets.set(key, current);
    return { allowed: false, retryAfter, remaining: 0 };
  }
  current.push(now);
  rateBuckets.set(key, current);

  if (rateBuckets.size > 5_000) {
    for (const [bucketKey, timestamps] of rateBuckets) {
      if (!timestamps.some((timestamp) => timestamp > cutoff)) rateBuckets.delete(bucketKey);
      if (rateBuckets.size <= 4_000) break;
    }
  }
  return { allowed: true, retryAfter: 0, remaining: Math.max(0, limit - current.length) };
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

function externalUrlBlockReason(value: string, freshSubmission = false): string | null {
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
  if (freshSubmission) {
    for (const key of parsed.searchParams.keys()) {
      if (/^(?:access_?token|auth|authorization|code|credential|jwt|otp|pass(?:word|code)?|reset(?:_?token)?|session(?:id)?|signature|sig|secret|token)$/i.test(key)) {
        return "This URL appears to contain a sensitive access token or credential in its query parameters.";
      }
    }
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

function stripTrailingPunctuation(value: string) {
  return value.replace(/[),.;!?\]}>'"]+$/g, "");
}

function extractUrls(message: string) {
  const candidates = message.match(/(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi) ?? [];
  const urls: string[] = [];
  for (const candidate of candidates) {
    const cleaned = stripTrailingPunctuation(candidate);
    const withScheme = /^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`;
    try {
      const parsed = new URL(withScheme);
      if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname.includes(".")) continue;
      parsed.hash = "";
      if (parsed.href.length > MAX_URL_LENGTH) continue;
      if (!urls.includes(parsed.href)) urls.push(parsed.href);
    } catch {
      continue;
    }
    if (urls.length >= MAX_URLS) break;
  }
  return urls;
}

function countPatternMatches(message: string, patterns: RegExp[]) {
  return patterns.reduce((count, pattern) => count + (pattern.test(message) ? 1 : 0), 0);
}

function messageAnalysis(message: string, urls: string[]) {
  const normalizedMessage = message.normalize("NFKC").replace(/\s+/g, " ").trim();
  const categoryScores = categoryRules.map((rule) => {
    const hits = countPatternMatches(normalizedMessage, rule.patterns);
    return { type: rule.type, score: hits * rule.weight, hits };
  });
  categoryScores.sort((a, b) => b.score - a.score);

  const urgencyHits = countPatternMatches(normalizedMessage, urgencyPatterns);
  const credentialHits = countPatternMatches(normalizedMessage, credentialPatterns);
  const paymentHits = countPatternMatches(normalizedMessage, paymentPatterns);
  const consequenceHits = countPatternMatches(normalizedMessage, consequencePatterns);
  const rewardHits = countPatternMatches(normalizedMessage, rewardPatterns);
  const callToActionHits = countPatternMatches(normalizedMessage, callToActionPatterns);
  const impersonationHits = countPatternMatches(normalizedMessage, impersonationPatterns);
  const uppercaseWords = message.match(/\b[A-ZČĆŽŠĐ]{4,}\b/g)?.length ?? 0;
  const exclamations = Math.min(3, (message.match(/!/g) ?? []).length);

  let score = 5;
  score += Math.min(30, categoryScores.reduce((sum, category) => sum + category.score, 0));
  score += Math.min(16, urgencyHits * 8);
  score += Math.min(20, credentialHits * 10);
  score += Math.min(18, paymentHits * 9);
  score += Math.min(16, consequenceHits * 8);
  score += Math.min(14, rewardHits * 7);
  score += Math.min(12, callToActionHits * 4);
  score += Math.min(10, impersonationHits * 5);
  score += Math.min(6, uppercaseWords * 2);
  score += exclamations * 2;
  if (urls.length) score += 7;
  const combinedSocialSignals = urgencyHits + credentialHits + paymentHits + consequenceHits + rewardHits + callToActionHits + impersonationHits;
  const strongestCategoryHits = categoryScores[0]?.hits ?? 0;
  if (strongestCategoryHits >= 2 && combinedSocialSignals >= 3) score = Math.max(score, 72);
  else if (strongestCategoryHits >= 1 && (combinedSocialSignals >= 2 || (urls.length > 0 && callToActionHits > 0))) score = Math.max(score, 45);

  const reasons: string[] = [];
  if (categoryScores[0]?.hits) reasons.push(`The wording matches a common ${categoryScores[0].type.toLowerCase()} pattern.`);
  if (urgencyHits) reasons.push("The message creates urgency or a short deadline to reduce careful checking.");
  if (credentialHits) reasons.push("It asks for login, verification, or other sensitive account information.");
  if (paymentHits) reasons.push("It mentions a payment method or transfer commonly abused in scams.");
  if (consequenceHits) reasons.push("It threatens account restrictions, data loss, or another consequence to pressure the recipient.");
  if (rewardHits) reasons.push("It uses a reward, payout, guaranteed return, or unusually attractive offer as a lure.");
  if (callToActionHits) reasons.push("It pushes the recipient toward an immediate reply, call, payment, registration, or linked page.");
  if (impersonationHits) reasons.push("The wording imitates a recognizable company or official support team.");
  if (uppercaseWords || exclamations >= 2) reasons.push("The formatting uses pressure signals such as capitals or repeated exclamation marks.");
  if (urls.length) reasons.push(`${urls.length} link${urls.length === 1 ? " was" : "s were"} found and checked separately.`);

  if (!reasons.length) reasons.push("No strong social-engineering pattern was found in the supplied text.");
  const signals = [
    {
      name: "Urgency & pressure",
      count: urgencyHits,
      state: urgencyHits >= 2 ? "danger" : urgencyHits === 1 ? "warning" : "clear",
      detail: urgencyHits
        ? `${urgencyHits} urgency pattern${urgencyHits === 1 ? " was" : "s were"} detected.`
        : "No forced deadline or urgency phrase was detected.",
    },
    {
      name: "Sensitive information",
      count: credentialHits,
      state: credentialHits > 0 ? "danger" : "clear",
      detail: credentialHits
        ? `${credentialHits} request${credentialHits === 1 ? "" : "s"} related to login, identity, or verification data were detected.`
        : "No request for passwords, login details, or verification codes was detected.",
    },
    {
      name: "Payment language",
      count: paymentHits,
      state: paymentHits >= 2 ? "danger" : paymentHits === 1 ? "warning" : "clear",
      detail: paymentHits
        ? `${paymentHits} payment or transfer signal${paymentHits === 1 ? " was" : "s were"} detected.`
        : "No common payment-pressure phrase was detected.",
    },
    {
      name: "Aggressive formatting",
      count: uppercaseWords + exclamations,
      state: uppercaseWords + exclamations >= 4 ? "warning" : "clear",
      detail: uppercaseWords || exclamations
        ? `${uppercaseWords} uppercase word${uppercaseWords === 1 ? "" : "s"} and ${exclamations} emphasized exclamation mark${exclamations === 1 ? "" : "s"} were counted.`
        : "No strong formatting-pressure signal was detected.",
    },
    {
      name: "Threatened consequences",
      count: consequenceHits,
      state: consequenceHits >= 2 ? "danger" : consequenceHits === 1 ? "warning" : "clear",
      detail: consequenceHits
        ? `${consequenceHits} threat of account restriction, failed payment, or data loss was detected.`
        : "No threat of suspension, freezing, deletion, or failed credit was detected.",
    },
    {
      name: "Reward or profit lure",
      count: rewardHits,
      state: rewardHits >= 2 ? "danger" : rewardHits === 1 ? "warning" : "clear",
      detail: rewardHits
        ? `${rewardHits} reward, payout, bonus, or profit lure was detected.`
        : "No prize, bonus, guaranteed profit, or unexpected payout was detected.",
    },
    {
      name: "Forced call to action",
      count: callToActionHits,
      state: callToActionHits >= 2 ? "danger" : callToActionHits === 1 ? "warning" : "clear",
      detail: callToActionHits
        ? `${callToActionHits} instruction to call, reply, register, pay, or open a link was detected.`
        : "No suspicious instruction to reply, call, register, pay, or open a link was detected.",
    },
    {
      name: "Brand impersonation",
      count: impersonationHits,
      state: impersonationHits >= 2 ? "danger" : impersonationHits === 1 ? "warning" : "clear",
      detail: impersonationHits
        ? `${impersonationHits} phrase associated with brand or support-team impersonation was detected.`
        : "No strong brand or official-support impersonation phrase was detected.",
    },
  ] as const;

  const strongestCategory = categoryScores[0]?.hits ? categoryScores[0].type : null;
  const inferredType = credentialHits && (urgencyHits || consequenceHits || urls.length)
    ? "Credential phishing / account takeover"
    : paymentHits && (urgencyHits || consequenceHits)
      ? "Payment-pressure / advance-fee scam"
      : rewardHits && paymentHits
        ? "Reward / payment scam"
        : impersonationHits && (callToActionHits || urls.length)
          ? "Brand impersonation / social engineering"
          : urls.length && callToActionHits
            ? "Suspicious link solicitation"
            : urgencyHits || consequenceHits
              ? "Social-engineering pressure"
              : "No specific scam category identified";

  const words = message.match(/\S+/g)?.length ?? 0;
  const lines = message ? message.split(/\r?\n/).length : 0;
  return {
    score: Math.min(96, score),
    scamType: strongestCategory ?? inferredType,
    reasons,
    indicators: { urgency: urgencyHits, credentials: credentialHits, payment: paymentHits },
    signals,
    categories: categoryScores.filter((category) => category.hits > 0).slice(0, 4),
    stats: {
      characters: message.length,
      words,
      lines,
      uppercaseWords,
      exclamations,
    },
  };
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

async function rdapDomainAge(domain: string, env: ScannerEnv, ctx?: ScannerContext): Promise<{ provider: ProviderResult; ageDays: number | null; riskBoost: number }> {
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return {
      provider: { name: "RDAP domain age", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true },
      ageDays: 3_650,
      riskBoost: 0,
    };
  }

  return cachedResult("rdap-age", domain, 86_400, async () => {
    try {
      const response = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { headers: { accept: "application/rdap+json, application/json" } });
      if (response.status === 404) {
        return {
          provider: { name: "RDAP domain age", state: "warning", label: "No record", detail: "No public RDAP registration record was found for this domain.", configured: true },
          ageDays: null,
          riskBoost: 16,
        };
      }
      if (!response.ok) throw new Error("rdap unavailable");
      const data = await readProviderJson(response);
      const events = Array.isArray(data?.events) ? data.events : [];
      const registration = events.find((event): event is { eventAction?: string; eventDate?: string } =>
        Boolean(event && typeof event === "object" && /registration/i.test(String((event as Record<string, unknown>).eventAction ?? ""))),
      );
      if (!registration?.eventDate) {
        return {
          provider: { name: "RDAP domain age", state: "unavailable", label: "Unknown", detail: "The registration record does not publish a creation date.", configured: true },
          ageDays: null,
          riskBoost: 4,
        };
      }
      const ageDays = Math.max(0, Math.floor((Date.now() - new Date(registration.eventDate).getTime()) / 86_400_000));
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
  }, ctx);
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

async function analyzeLink(url: string, mode: "quick" | "deep", env: ScannerEnv, ctx?: ScannerContext): Promise<LinkReport> {
  const providerUrl = normalizedProviderUrl(url);
  const structural = inspectUrl(providerUrl);
  const externalBlock = externalUrlBlockReason(providerUrl);
  if (externalBlock) {
    return {
      url: providerUrl,
      domain: structural.domain,
      riskScore: Math.min(99, Math.max(structural.score, 34)),
      reasons: [externalBlock, ...structural.reasons].slice(0, 7),
      providers: [
        { name: "Google Safe Browsing", state: "not-run", label: "Protected", detail: externalBlock, configured: Boolean(env.GOOGLE_API_KEY) },
        { name: "RDAP domain age", state: "not-run", label: "Protected", detail: externalBlock, configured: true },
        { name: "VirusTotal", state: "not-run", label: "Protected", detail: externalBlock, configured: Boolean(env.VIRUSTOTAL_API_KEY) },
      ],
      domainAgeDays: null,
      virusTotal: null,
      technical: structural.technical,
    };
  }
  const [google, rdap, vt] = await Promise.all([
    googleSafeBrowsing(providerUrl, env, ctx),
    rdapDomainAge(structural.domain, env, ctx),
    mode === "deep"
      ? virusTotalExisting(providerUrl, env, ctx)
      : Promise.resolve({
          provider: { name: "VirusTotal", state: "not-run" as const, label: "Deep Scan only", detail: "Run Deep Scan to check the latest existing VirusTotal report.", configured: Boolean(env.VIRUSTOTAL_API_KEY) },
          report: null,
          riskBoost: 0,
        }),
  ]);

  let riskScore = structural.score + rdap.riskBoost;
  if (google.state === "danger") riskScore = Math.max(riskScore, 94);
  riskScore = Math.max(riskScore, vt.riskBoost);
  const reasons = [...structural.reasons];
  if (google.state === "danger") reasons.unshift("Google Safe Browsing returned a known-threat match.");
  if (rdap.riskBoost >= 12) reasons.push(rdap.provider.detail);
  if (vt.riskBoost >= 72) reasons.unshift(vt.provider.detail);

  return {
    url: providerUrl,
    domain: structural.domain,
    riskScore: Math.min(99, riskScore),
    reasons: reasons.slice(0, 7),
    providers: [google, rdap.provider, vt.provider],
    domainAgeDays: rdap.ageDays,
    virusTotal: vt.report,
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

async function runScan(message: string, mode: "quick" | "deep", env: ScannerEnv, ctx?: ScannerContext) {
  const scanStartedAt = performance.now();
  const urls = extractUrls(message);
  const local = messageAnalysis(message, urls);
  const localAnalysisMs = Math.round(performance.now() - scanStartedAt);
  const liveChecksStartedAt = performance.now();
  const links = await Promise.all(urls.map((url) => analyzeLink(url, mode, env, ctx)));
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
          state: mode === "deep" ? "not-run" : "not-run",
          label: "No URL",
          detail: "VirusTotal analyzes URLs, and this input contains no link.",
          configured: Boolean(env.VIRUSTOTAL_API_KEY),
          subject: "Message only",
        },
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
    analysis: {
      inputType: urls.length === 0 ? "Message" : messageWithoutUrls.length < 8 ? "URL" : "Message + URL",
      rulesEvaluated:
        categoryRules.reduce((sum, rule) => sum + rule.patterns.length, 0) +
        urgencyPatterns.length +
        credentialPatterns.length +
        paymentPatterns.length +
        consequencePatterns.length +
        rewardPatterns.length +
        callToActionPatterns.length +
        impersonationPatterns.length,
      messageStats: local.stats,
      signals: local.signals,
      categoryMatches: local.categories,
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
        "Submitting starts a new VirusTotal analysis. The URL and resulting report may be shared with VirusTotal and its security community. Do not submit private, one-time, internal, or credential-bearing links.",
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
  const rate = checkRateLimit(await getRateKey(request, mode), limit, 60);
  if (!rate.allowed) {
    return jsonResponse({ error: `Too many ${mode} scans. Try again in ${rate.retryAfter} seconds.` }, 429, { "retry-after": String(rate.retryAfter) });
  }

  const verification = await validateTurnstile(request, env, body.turnstileToken);
  if (verification.misconfigured) {
    return jsonResponse({ error: "Human verification is temporarily unavailable." }, 503);
  }
  if (!verification.valid) {
    return jsonResponse({ error: "Human verification failed or expired. Please complete it again.", verificationRequired: true }, 403);
  }

  const result = await runScan(message, mode, env, ctx);
  return jsonResponse(result, 200, {
    "x-ratelimit-limit": String(limit),
    "x-ratelimit-remaining": String(rate.remaining),
  });
}

async function handleDeepSubmit(request: Request, env: ScannerEnv) {
  const parsedBody = await parseJsonObject(request, MAX_DEEP_BODY_BYTES);
  if (parsedBody.response) return parsedBody.response;
  const body = parsedBody.body ?? {};
  if (body.consent !== true) return jsonResponse({ error: "Explicit consent is required before sending a URL to VirusTotal." }, 400);
  if (!env.VIRUSTOTAL_API_KEY) return jsonResponse({ error: "Fresh VirusTotal analysis is not configured on this deployment." }, 503);

  const urlValue = typeof body.url === "string" ? body.url.trim() : "";
  const urlBlock = externalUrlBlockReason(urlValue, true);
  if (urlBlock) return jsonResponse({ error: urlBlock }, 400);
  const parsed = new URL(normalizedProviderUrl(urlValue));

  const rate = checkRateLimit(await getRateKey(request, "deep-submit"), 2, 600);
  if (!rate.allowed) {
    return jsonResponse({ error: `Fresh analysis limit reached. Try again in ${rate.retryAfter} seconds.` }, 429, { "retry-after": String(rate.retryAfter) });
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

  const rate = checkRateLimit(await getRateKey(request, "deep-status"), 30, 60);
  if (!rate.allowed) return jsonResponse({ error: "Polling too quickly. Wait a moment and try again." }, 429, { "retry-after": String(rate.retryAfter) });

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
    "/api/deep/submit": "POST",
    "/api/deep/status": "GET",
  };
  const allowedMethod = methods[url.pathname];
  if (allowedMethod && request.method !== allowedMethod) {
    return jsonResponse({ error: "Method not allowed." }, 405, { allow: allowedMethod });
  }
  if ((url.pathname === "/api/scan" || url.pathname === "/api/deep/submit") && !isTrustedWriteRequest(request)) {
    return jsonResponse({ error: "Cross-site requests are not allowed." }, 403);
  }
  if (url.pathname === "/api/scan") return handleScan(request, env, ctx);
  if (url.pathname === "/api/deep/submit") return handleDeepSubmit(request, env);
  if (url.pathname === "/api/deep/status") return handleDeepStatus(request, env);
  if (url.pathname.startsWith("/api/") || url.pathname === "/health") {
    return jsonResponse({ error: "Not found." }, 404);
  }
  return null;
}
