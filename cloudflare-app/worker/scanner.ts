export interface ScannerEnv {
  GOOGLE_API_KEY?: string;
  VIRUSTOTAL_API_KEY?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
  DISABLE_EXTERNAL_CHECKS?: string;
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
}

interface ScanBody {
  message?: unknown;
  mode?: unknown;
  turnstileToken?: unknown;
}

interface DeepSubmitBody {
  url?: unknown;
  consent?: unknown;
  turnstileToken?: unknown;
}

interface Rule {
  type: string;
  patterns: RegExp[];
  weight: number;
}

const MAX_MESSAGE_LENGTH = 10_000;
const MAX_URLS = 3;
const REQUEST_TIMEOUT_MS = 4_500;
const rateBuckets = new Map<string, number[]>();

const categoryRules: Rule[] = [
  {
    type: "Account takeover / phishing",
    weight: 16,
    patterns: [
      /verify (?:your )?(?:account|identity|login)/i,
      /confirm (?:your )?(?:password|login|identity)/i,
      /nalog (?:je )?(?:blokiran|zaključan)/i,
      /potvrd(?:i|ite) (?:nalog|identitet|lozinku)/i,
      /unusual (?:login|activity)/i,
      /password expires?/i,
    ],
  },
  {
    type: "Delivery / postal scam",
    weight: 13,
    patterns: [
      /(?:parcel|package|delivery).*(?:fee|address|failed|held)/i,
      /(?:paket|pošiljka|dostava).*(?:naknada|adresa|zadržan|neuspjel)/i,
      /customs (?:fee|charge)/i,
    ],
  },
  {
    type: "Investment / crypto scam",
    weight: 15,
    patterns: [
      /guaranteed (?:return|profit)/i,
      /double your (?:money|crypto)/i,
      /sigurn(?:a|i) (?:zarada|profit)/i,
      /invest.*(?:crypto|bitcoin|forex)/i,
      /wallet (?:validation|synchronization)/i,
    ],
  },
  {
    type: "Prize / advance-fee scam",
    weight: 14,
    patterns: [
      /(?:won|winner|prize|lottery).*(?:fee|claim|pay)/i,
      /(?:osvojili|dobitnik|nagrada).*(?:naknada|preuzm|uplati)/i,
      /processing fee/i,
      /inheritance.*(?:fee|transfer)/i,
    ],
  },
  {
    type: "Job scam",
    weight: 12,
    patterns: [
      /(?:easy|remote) (?:job|work).*(?:daily|weekly|earn)/i,
      /posao od kuće.*(?:zarad|dnevno|sedmično)/i,
      /pay.*(?:training|equipment).*(?:job|position)/i,
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
  if (!env.TURNSTILE_SECRET_KEY) return { valid: true, configured: false };
  if (typeof token !== "string" || !token.trim()) return { valid: false, configured: true };

  try {
    const response = await fetchWithTimeout("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        secret: env.TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: getClientIp(request),
      }),
    });
    const result = (await response.json()) as { success?: boolean };
    return { valid: result.success === true, configured: true };
  } catch {
    return { valid: false, configured: true };
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

async function cachedResult<T>(namespace: string, identifier: string, ttlSeconds: number, producer: () => Promise<T>) {
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
  try {
    await cache.put(
      key,
      new Response(JSON.stringify(result), {
        headers: {
          "content-type": "application/json",
          "cache-control": `public, max-age=${ttlSeconds}`,
        },
      }),
    );
  } catch {
    // Cache failures should never stop a scan.
  }
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
  const categoryScores = categoryRules.map((rule) => {
    const hits = countPatternMatches(message, rule.patterns);
    return { type: rule.type, score: hits * rule.weight, hits };
  });
  categoryScores.sort((a, b) => b.score - a.score);

  const urgencyHits = countPatternMatches(message, urgencyPatterns);
  const credentialHits = countPatternMatches(message, credentialPatterns);
  const paymentHits = countPatternMatches(message, paymentPatterns);
  const uppercaseWords = message.match(/\b[A-ZČĆŽŠĐ]{4,}\b/g)?.length ?? 0;
  const exclamations = Math.min(3, (message.match(/!/g) ?? []).length);

  let score = 5;
  score += Math.min(30, categoryScores.reduce((sum, category) => sum + category.score, 0));
  score += Math.min(16, urgencyHits * 8);
  score += Math.min(20, credentialHits * 10);
  score += Math.min(18, paymentHits * 9);
  score += Math.min(6, uppercaseWords * 2);
  score += exclamations * 2;
  if (urls.length) score += 7;

  const reasons: string[] = [];
  if (categoryScores[0]?.hits) reasons.push(`The wording matches a common ${categoryScores[0].type.toLowerCase()} pattern.`);
  if (urgencyHits) reasons.push("The message creates urgency or a short deadline to reduce careful checking.");
  if (credentialHits) reasons.push("It asks for login, verification, or other sensitive account information.");
  if (paymentHits) reasons.push("It mentions a payment method or transfer commonly abused in scams.");
  if (uppercaseWords || exclamations >= 2) reasons.push("The formatting uses pressure signals such as capitals or repeated exclamation marks.");
  if (urls.length) reasons.push(`${urls.length} link${urls.length === 1 ? " was" : "s were"} found and checked separately.`);

  if (!reasons.length) reasons.push("No strong social-engineering pattern was found in the supplied text.");
  return {
    score: Math.min(96, score),
    scamType: categoryScores[0]?.hits ? categoryScores[0].type : "No dominant scam pattern",
    reasons,
    indicators: { urgency: urgencyHits, credentials: credentialHits, payment: paymentHits },
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
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain)) {
    score += 28;
    reasons.push("The link uses a raw IP address instead of a normal domain name.");
  }
  if (domain.startsWith("xn--")) {
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
  return { domain, score: Math.min(92, score), reasons };
}

function unavailableProvider(name: string, detail: string, configured = false): ProviderResult {
  return { name, state: "unavailable", label: configured ? "Unavailable" : "Not configured", detail, configured };
}

async function googleSafeBrowsing(url: string, env: ScannerEnv): Promise<ProviderResult> {
  if (!env.GOOGLE_API_KEY) {
    return unavailableProvider("Google Safe Browsing", "Add GOOGLE_API_KEY to enable live threat-list checks.");
  }
  if (isEnabled(env.DISABLE_EXTERNAL_CHECKS)) {
    return { name: "Google Safe Browsing", state: "clear", label: "Test mode", detail: "External checks are disabled in this test run.", configured: true };
  }

  return cachedResult("gsb-v5", url, 300, async () => {
    try {
      const endpoint = new URL("https://safebrowsing.googleapis.com/v5/urls:search");
      endpoint.searchParams.set("key", env.GOOGLE_API_KEY ?? "");
      endpoint.searchParams.append("urls", url);
      const response = await fetchWithTimeout(endpoint, { headers: { accept: "application/json" } });
      if (!response.ok) {
        return unavailableProvider("Google Safe Browsing", `The provider returned HTTP ${response.status}.`, true);
      }
      const data = (await response.json()) as { threats?: unknown[] };
      const flagged = Array.isArray(data.threats) && data.threats.length > 0;
      return flagged
        ? { name: "Google Safe Browsing", state: "danger", label: "Threat match", detail: "Google Safe Browsing lists this URL as a known threat.", configured: true }
        : { name: "Google Safe Browsing", state: "clear", label: "No match", detail: "No current Google Safe Browsing threat-list match was returned.", configured: true };
    } catch {
      return unavailableProvider("Google Safe Browsing", "The check timed out or could not be reached.", true);
    }
  });
}

async function rdapDomainAge(domain: string, env: ScannerEnv): Promise<{ provider: ProviderResult; ageDays: number | null; riskBoost: number }> {
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
      const data = (await response.json()) as { events?: Array<{ eventAction?: string; eventDate?: string }> };
      const registration = data.events?.find((event) => /registration/i.test(event.eventAction ?? ""));
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
  });
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

async function virusTotalExisting(url: string, env: ScannerEnv): Promise<{ provider: ProviderResult; report: LinkReport["virusTotal"]; riskBoost: number }> {
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
      const data = (await response.json()) as {
        data?: { attributes?: { last_analysis_stats?: Record<string, number>; last_analysis_date?: number } };
      };
      const stats = data.data?.attributes?.last_analysis_stats ?? null;
      const lastAnalysisDate = data.data?.attributes?.last_analysis_date ?? null;
      const verdict = vtVerdict(stats);
      return {
        provider: {
          name: "VirusTotal",
          state: verdict.state,
          label: verdict.label,
          detail: stats
            ? `Existing report: ${stats.malicious ?? 0} malicious, ${stats.suspicious ?? 0} suspicious, ${stats.harmless ?? 0} harmless verdicts.`
            : "An existing object was found, but it contains no current engine summary.",
          configured: true,
        },
        report: { found: true, stats, lastAnalysisDate },
        riskBoost: verdict.boost,
      };
    } catch {
      return { provider: unavailableProvider("VirusTotal", "The existing-report check timed out or was unavailable.", true), report: null, riskBoost: 0 };
    }
  });
}

async function analyzeLink(url: string, mode: "quick" | "deep", env: ScannerEnv): Promise<LinkReport> {
  const structural = inspectUrl(url);
  const [google, rdap, vt] = await Promise.all([
    googleSafeBrowsing(url, env),
    rdapDomainAge(structural.domain, env),
    mode === "deep"
      ? virusTotalExisting(url, env)
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
    url,
    domain: structural.domain,
    riskScore: Math.min(99, riskScore),
    reasons: reasons.slice(0, 4),
    providers: [google, rdap.provider, vt.provider],
    domainAgeDays: rdap.ageDays,
    virusTotal: vt.report,
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

async function runScan(message: string, mode: "quick" | "deep", env: ScannerEnv) {
  const urls = extractUrls(message);
  const local = messageAnalysis(message, urls);
  const links = await Promise.all(urls.map((url) => analyzeLink(url, mode, env)));

  const maxLinkRisk = links.reduce((max, link) => Math.max(max, link.riskScore), 0);
  let riskPercent = Math.round(local.score * (links.length ? 0.64 : 1) + maxLinkRisk * (links.length ? 0.36 : 0));
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
  const reasons = [...new Set(combinedReasons)].slice(0, 3);
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
        { ...unavailableProvider("Google Safe Browsing", "No URL was found in the supplied text.", Boolean(env.GOOGLE_API_KEY)), subject: "Message only" },
        { ...unavailableProvider("RDAP domain age", "No domain was found in the supplied text.", true), subject: "Message only" },
        {
          name: "VirusTotal",
          state: mode === "deep" ? "not-run" : "not-run",
          label: "No URL",
          detail: "VirusTotal analyzes URLs, and this input contains no link.",
          configured: Boolean(env.VIRUSTOTAL_API_KEY),
          subject: "Message only",
        },
      ];

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
    ].slice(0, 12),
    links,
    providers,
    iocs: extractIocs(message, urls),
    deepScan: {
      checkedExistingReport: mode === "deep" && urls.length > 0,
      canSubmitFreshAnalysis: mode === "deep" && urls.length > 0 && Boolean(env.VIRUSTOTAL_API_KEY),
      urls,
      privacyNotice:
        "Submitting starts a new VirusTotal analysis. The URL and resulting report may be shared with VirusTotal and its security community. Do not submit private, one-time, internal, or credential-bearing links.",
    },
    limits: { maxUrls: MAX_URLS, truncatedUrls: (message.match(/https?:\/\//gi)?.length ?? 0) > MAX_URLS },
  };
}

async function parseJson<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

async function handleScan(request: Request, env: ScannerEnv) {
  const body = await parseJson<ScanBody>(request);
  if (!body) return jsonResponse({ error: "Invalid JSON request." }, 400);

  const message = cleanMessage(body.message);
  const mode = body.mode === "deep" ? "deep" : "quick";
  if (!message) return jsonResponse({ error: "Paste a message or link before starting a scan." }, 400);
  if (message.length > MAX_MESSAGE_LENGTH) {
    return jsonResponse({ error: `Input is too long. The maximum is ${MAX_MESSAGE_LENGTH.toLocaleString()} characters.` }, 413);
  }

  const verification = await validateTurnstile(request, env, body.turnstileToken);
  if (!verification.valid) {
    return jsonResponse({ error: "Human verification failed or expired. Please complete it again.", verificationRequired: true }, 403);
  }

  const limit = mode === "deep" ? 5 : 20;
  const rate = checkRateLimit(`${getClientIp(request)}:${mode}`, limit, 60);
  if (!rate.allowed) {
    return jsonResponse({ error: `Too many ${mode} scans. Try again in ${rate.retryAfter} seconds.` }, 429, { "retry-after": String(rate.retryAfter) });
  }

  const result = await runScan(message, mode, env);
  return jsonResponse(result, 200, {
    "x-ratelimit-limit": String(limit),
    "x-ratelimit-remaining": String(rate.remaining),
  });
}

async function handleDeepSubmit(request: Request, env: ScannerEnv) {
  const body = await parseJson<DeepSubmitBody>(request);
  if (!body) return jsonResponse({ error: "Invalid JSON request." }, 400);
  if (body.consent !== true) return jsonResponse({ error: "Explicit consent is required before sending a URL to VirusTotal." }, 400);
  if (!env.VIRUSTOTAL_API_KEY) return jsonResponse({ error: "Fresh VirusTotal analysis is not configured on this deployment." }, 503);

  const verification = await validateTurnstile(request, env, body.turnstileToken);
  if (!verification.valid) {
    return jsonResponse({ error: "Human verification failed or expired. Please complete it again.", verificationRequired: true }, 403);
  }

  const urlValue = typeof body.url === "string" ? body.url.trim() : "";
  let parsed: URL;
  try {
    parsed = new URL(urlValue);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("unsupported scheme");
  } catch {
    return jsonResponse({ error: "A valid HTTP or HTTPS URL is required." }, 400);
  }

  const rate = checkRateLimit(`${getClientIp(request)}:deep-submit`, 2, 600);
  if (!rate.allowed) {
    return jsonResponse({ error: `Fresh analysis limit reached. Try again in ${rate.retryAfter} seconds.` }, 429, { "retry-after": String(rate.retryAfter) });
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
    const data = (await response.json().catch(() => ({}))) as { data?: { id?: string }; error?: { message?: string } };
    if (!response.ok || !data.data?.id) {
      return jsonResponse({ error: data.error?.message ?? `VirusTotal returned HTTP ${response.status}.` }, response.status === 429 ? 429 : 502);
    }
    return jsonResponse({
      analysisId: data.data.id,
      status: "queued",
      url: parsed.href,
      message: "VirusTotal accepted the URL. ScamShield will now track the analysis until it finishes.",
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

  const rate = checkRateLimit(`${getClientIp(request)}:deep-status`, 30, 60);
  if (!rate.allowed) return jsonResponse({ error: "Polling too quickly. Wait a moment and try again." }, 429, { "retry-after": String(rate.retryAfter) });

  try {
    const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, {
      headers: { "x-apikey": env.VIRUSTOTAL_API_KEY, accept: "application/json" },
    });
    const data = (await response.json().catch(() => ({}))) as {
      data?: { attributes?: { status?: string; stats?: Record<string, number>; date?: number } };
      error?: { message?: string };
    };
    if (!response.ok) return jsonResponse({ error: data.error?.message ?? `VirusTotal returned HTTP ${response.status}.` }, response.status === 429 ? 429 : 502);
    const attributes = data.data?.attributes ?? {};
    const status = attributes.status ?? "queued";
    const stats = attributes.stats ?? null;
    const verdict = vtVerdict(stats);
    return jsonResponse({
      status,
      completed: status === "completed",
      stats,
      verdict: status === "completed" ? verdict.label : null,
      riskState: status === "completed" ? verdict.state : "pending",
      analyzedAt: attributes.date ?? null,
    });
  } catch {
    return jsonResponse({ error: "Analysis status could not be retrieved." }, 502);
  }
}

export async function handleScannerApi(request: Request, env: ScannerEnv): Promise<Response | null> {
  const url = new URL(request.url);

  if (url.pathname === "/health" && request.method === "GET") {
    return jsonResponse({ status: "ok", service: "ScamShield", runtime: "cloudflare-worker" });
  }
  if (url.pathname === "/api/config" && request.method === "GET") {
    return jsonResponse({
      turnstileSiteKey: env.TURNSTILE_SITE_KEY ?? null,
      turnstileConfigured: Boolean(env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET_KEY),
      providers: {
        googleSafeBrowsing: Boolean(env.GOOGLE_API_KEY),
        virusTotal: Boolean(env.VIRUSTOTAL_API_KEY),
        rdap: true,
      },
    });
  }
  if (url.pathname === "/api/scan" && request.method === "POST") return handleScan(request, env);
  if (url.pathname === "/api/deep/submit" && request.method === "POST") return handleDeepSubmit(request, env);
  if (url.pathname === "/api/deep/status" && request.method === "GET") return handleDeepStatus(request, env);
  if (url.pathname.startsWith("/api/") || url.pathname === "/health") {
    return jsonResponse({ error: "Not found." }, 404);
  }
  return null;
}
