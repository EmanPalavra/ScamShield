export type DomainIntelState = "clear" | "warning" | "danger" | "unavailable" | "not-run";

export interface DomainIntelProvider {
  name: string;
  state: DomainIntelState;
  label: string;
  detail: string;
  configured: boolean;
}

export interface DomainIntelligence {
  brand: {
    state: "clear" | "warning" | "danger";
    suspectedBrand: string | null;
    officialDomain: string | null;
    similarity: number;
    distance: number | null;
    isTyposquat: boolean;
    signals: string[];
  };
  dns: {
    state: DomainIntelState;
    addresses: string[];
    ipv6: string[];
    nameservers: string[];
    mailServers: string[];
    cname: string | null;
    minTtl: number | null;
    dnssecAuthenticated: boolean | null;
  };
  certificate: {
    state: DomainIntelState;
    source: "Certificate Transparency";
    recordCount: number;
    activeRecordCount: number;
    latestExpiry: string | null;
    issuer: string | null;
    names: string[];
  };
  redirects: {
    state: DomainIntelState;
    checked: boolean;
    count: number;
    chain: Array<{ url: string; domain: string; status: number }>;
    finalUrl: string;
    crossedDomains: boolean;
    bodyFetched: false;
    detail: string;
  };
}

export interface DomainIntelligenceResult {
  intelligence: DomainIntelligence;
  providers: DomainIntelProvider[];
  riskBoost: number;
  riskFloor: number;
  reasons: string[];
}

interface AnalysisOptions {
  externalDisabled: boolean;
  protectedReason?: string | null;
  ctx?: { waitUntil(promise: Promise<unknown>): void };
}

interface DnsJson {
  Status?: number;
  AD?: boolean;
  Answer?: Array<{ name?: string; type?: number; TTL?: number; data?: string }>;
}

interface DnsLookup {
  state: DomainIntelState;
  addresses: string[];
  ipv6: string[];
  nameservers: string[];
  mailServers: string[];
  cname: string | null;
  minTtl: number | null;
  dnssecAuthenticated: boolean | null;
  detail: string;
}

const REQUEST_TIMEOUT_MS = 3_800;
const DNS_RESPONSE_LIMIT = 96 * 1024;
const CT_RESPONSE_LIMIT = 384 * 1024;
const MAX_REDIRECTS = 4;

const brands = [
  ["PayPal", "paypal.com"],
  ["Microsoft", "microsoft.com"],
  ["Apple", "apple.com"],
  ["Google", "google.com"],
  ["Amazon", "amazon.com"],
  ["Netflix", "netflix.com"],
  ["Facebook", "facebook.com"],
  ["Instagram", "instagram.com"],
  ["WhatsApp", "whatsapp.com"],
  ["DHL", "dhl.com"],
  ["UPS", "ups.com"],
  ["FedEx", "fedex.com"],
  ["Coinbase", "coinbase.com"],
  ["Binance", "binance.com"],
  ["Wise", "wise.com"],
  ["Revolut", "revolut.com"],
  ["Stripe", "stripe.com"],
  ["Dropbox", "dropbox.com"],
  ["LinkedIn", "linkedin.com"],
  ["eBay", "ebay.com"],
  ["Booking.com", "booking.com"],
] as const;

const lureWords = new Set(["secure", "login", "account", "verify", "verification", "support", "auth", "update", "wallet", "billing"]);

function hostnameWithoutWww(hostname: string) {
  return hostname.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
}

function officialHost(hostname: string, officialDomain: string) {
  return hostname === officialDomain || hostname.endsWith(`.${officialDomain}`);
}

function brandKey(value: string) {
  return value.toLowerCase().replace(/\.com$/, "").replace(/[^a-z0-9]/g, "");
}

function confusableKey(value: string) {
  return brandKey(value)
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/7/g, "t");
}

function levenshtein(left: string, right: string) {
  const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let row = 1; row <= left.length; row += 1) {
    let diagonal = previous[0];
    previous[0] = row;
    for (let column = 1; column <= right.length; column += 1) {
      const above = previous[column];
      previous[column] = Math.min(
        previous[column] + 1,
        previous[column - 1] + 1,
        diagonal + (left[row - 1] === right[column - 1] ? 0 : 1),
      );
      diagonal = above;
    }
  }
  return previous[right.length];
}

function inspectBrand(hostname: string): DomainIntelligence["brand"] {
  const domain = hostnameWithoutWww(hostname);
  const labels = domain.split(".").slice(0, -1);
  const tokens = labels.flatMap((label) => label.split("-")).filter(Boolean);
  const candidates = [...new Set([...tokens, labels.join(""), confusableKey(labels.join(""))])];
  let best: {
    brand: string;
    officialDomain: string;
    similarity: number;
    distance: number;
    candidate: string;
  } | null = null;

  for (const [brand, officialDomain] of brands) {
    if (officialHost(domain, officialDomain)) {
      return {
        state: "clear",
        suspectedBrand: brand,
        officialDomain,
        similarity: 100,
        distance: 0,
        isTyposquat: false,
        signals: ["Official domain or subdomain"],
      };
    }
    const expected = brandKey(brand);
    for (const rawCandidate of candidates) {
      const candidate = confusableKey(rawCandidate);
      if (!candidate || candidate.length < 3) continue;
      const distance = levenshtein(candidate, expected);
      const similarity = Math.round((1 - distance / Math.max(candidate.length, expected.length)) * 100);
      if (!best || similarity > best.similarity || (similarity === best.similarity && distance < best.distance)) {
        best = { brand, officialDomain, similarity, distance, candidate: rawCandidate };
      }
    }
  }

  const lureMatches = tokens.filter((token) => lureWords.has(token.toLowerCase()));
  const exactBrand = best?.similarity === 100;
  const closeBrand = Boolean(best && (best.distance === 1 || best.similarity >= 82));
  const possibleBrand = Boolean(best && (best.distance === 2 || best.similarity >= 72));
  const signals: string[] = [];
  if (exactBrand) signals.push("Brand name used outside its official domain");
  else if (closeBrand) signals.push("One-character or look-alike brand variation");
  else if (possibleBrand) signals.push("Domain resembles a known brand");
  if (lureMatches.length) signals.push(`Account-related wording: ${lureMatches.slice(0, 3).join(", ")}`);

  const danger = exactBrand || closeBrand;
  const warning = possibleBrand && (lureMatches.length > 0 || (best?.similarity ?? 0) >= 78);
  return {
    state: danger ? "danger" : warning ? "warning" : "clear",
    suspectedBrand: danger || warning ? best?.brand ?? null : null,
    officialDomain: danger || warning ? best?.officialDomain ?? null : null,
    similarity: danger || warning ? Math.max(0, best?.similarity ?? 0) : 0,
    distance: danger || warning ? best?.distance ?? null : null,
    isTyposquat: danger || warning,
    signals,
  };
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

async function readBoundedText(response: Response, maxBytes: number) {
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > maxBytes) throw new Error("response too large");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error("response too large");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

async function cacheKey(namespace: string, identifier: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(identifier));
  const hash = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return new Request(`https://scamshield-domain-cache.invalid/${namespace}/${hash}`);
}

async function cachedResult<T>(
  namespace: string,
  identifier: string,
  ttlSeconds: number,
  producer: () => Promise<T>,
  ctx?: AnalysisOptions["ctx"],
) {
  const storage = globalThis.caches as CacheStorage & { default?: Cache };
  const cache = storage?.default;
  if (!cache) return producer();
  const key = await cacheKey(namespace, identifier);
  try {
    const cached = await cache.match(key);
    if (cached) return (await cached.json()) as T;
  } catch {
    // Cache availability must not determine whether a scan completes.
  }
  const result = await producer();
  const write = cache.put(key, new Response(JSON.stringify(result), {
    headers: { "content-type": "application/json", "cache-control": `public, max-age=${ttlSeconds}` },
  })).catch(() => undefined);
  if (ctx) ctx.waitUntil(write);
  else await write;
  return result;
}

function cleanDnsValue(value: string | undefined) {
  return (value ?? "").trim().replace(/\.$/, "");
}

async function dnsQuery(domain: string, type: "A" | "AAAA" | "NS" | "MX") {
  const endpoint = new URL("https://cloudflare-dns.com/dns-query");
  endpoint.searchParams.set("name", domain);
  endpoint.searchParams.set("type", type);
  const response = await fetchWithTimeout(endpoint, { headers: { accept: "application/dns-json" } });
  if (!response.ok) throw new Error(`DNS HTTP ${response.status}`);
  const text = await readBoundedText(response, DNS_RESPONSE_LIMIT);
  return JSON.parse(text) as DnsJson;
}

function unique(values: string[]) {
  return [...new Set(values.filter(Boolean))];
}

async function lookupDns(domain: string, disabled: boolean, ctx?: AnalysisOptions["ctx"]): Promise<DnsLookup> {
  if (disabled) {
    return {
      state: "clear",
      addresses: ["93.184.216.34"],
      ipv6: [],
      nameservers: ["a.iana-servers.net", "b.iana-servers.net"],
      mailServers: [],
      cname: null,
      minTtl: 300,
      dnssecAuthenticated: true,
      detail: "Deterministic DNS data is being used because external checks are disabled.",
    };
  }
  return cachedResult("dns-v1", domain, 300, async () => {
   try {
    const responses = await Promise.all(["A", "AAAA", "NS", "MX"].map((type) => dnsQuery(domain, type as "A" | "AAAA" | "NS" | "MX")));
    const answers = responses.flatMap((response) => response.Answer ?? []);
    const addresses = unique(answers.filter((answer) => answer.type === 1).map((answer) => cleanDnsValue(answer.data)));
    const ipv6 = unique(answers.filter((answer) => answer.type === 28).map((answer) => cleanDnsValue(answer.data)));
    const nameservers = unique(answers.filter((answer) => answer.type === 2).map((answer) => cleanDnsValue(answer.data)));
    const mailServers = unique(answers.filter((answer) => answer.type === 15).map((answer) => cleanDnsValue(answer.data).replace(/^\d+\s+/, "")));
    const cname = unique(answers.filter((answer) => answer.type === 5).map((answer) => cleanDnsValue(answer.data)))[0] ?? null;
    const ttls = answers.map((answer) => answer.TTL).filter((ttl): ttl is number => typeof ttl === "number");
    const hasDestination = addresses.length > 0 || ipv6.length > 0 || Boolean(cname);
    return {
      state: hasDestination ? "clear" : "warning",
      addresses,
      ipv6,
      nameservers,
      mailServers,
      cname,
      minTtl: ttls.length ? Math.min(...ttls) : null,
      dnssecAuthenticated: responses.some((response) => response.AD === true),
      detail: hasDestination
        ? `${addresses.length + ipv6.length} address record${addresses.length + ipv6.length === 1 ? "" : "s"} and ${nameservers.length} name server${nameservers.length === 1 ? "" : "s"} were observed.`
        : "No public address or CNAME record was returned. The domain may be inactive or misconfigured.",
    };
   } catch {
    return {
      state: "unavailable",
      addresses: [],
      ipv6: [],
      nameservers: [],
      mailServers: [],
      cname: null,
      minTtl: null,
      dnssecAuthenticated: null,
      detail: "DNS records could not be retrieved within the safety limit.",
    };
   }
  }, ctx);
}

function issuerLabel(value: string | undefined) {
  const match = value?.match(/(?:^|,\s*)O=([^,]+)/i);
  return match?.[1]?.trim() ?? value?.split(",")[0]?.replace(/^[A-Z]+=/i, "").trim() ?? null;
}

async function inspectCertificate(domain: string, usesHttps: boolean, disabled: boolean, ctx?: AnalysisOptions["ctx"]): Promise<{
  intelligence: DomainIntelligence["certificate"];
  provider: DomainIntelProvider;
  riskBoost: number;
  reason: string | null;
}> {
  if (!usesHttps) {
    const detail = "The submitted URL uses HTTP, so no HTTPS certificate record was expected.";
    return {
      intelligence: { state: "warning", source: "Certificate Transparency", recordCount: 0, activeRecordCount: 0, latestExpiry: null, issuer: null, names: [] },
      provider: { name: "Certificate Transparency", state: "warning", label: "No HTTPS", detail, configured: true },
      riskBoost: 12,
      reason: "The destination uses unencrypted HTTP instead of HTTPS.",
    };
  }
  if (disabled) {
    const expiry = new Date(Date.now() + 180 * 86_400_000).toISOString();
    const detail = "A deterministic active Certificate Transparency record is being used in test mode.";
    return {
      intelligence: { state: "clear", source: "Certificate Transparency", recordCount: 1, activeRecordCount: 1, latestExpiry: expiry, issuer: "Test CA", names: [domain] },
      provider: { name: "Certificate Transparency", state: "clear", label: "Record found", detail, configured: true },
      riskBoost: 0,
      reason: null,
    };
  }
  return cachedResult("ct-v1", domain, 3_600, async () => {
   try {
    const endpoint = new URL("https://crt.sh/");
    endpoint.searchParams.set("q", domain);
    endpoint.searchParams.set("output", "json");
    endpoint.searchParams.set("exclude", "expired");
    const response = await fetchWithTimeout(endpoint, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`CT HTTP ${response.status}`);
    const text = await readBoundedText(response, CT_RESPONSE_LIMIT);
    const rows = JSON.parse(text) as Array<{ not_after?: string; issuer_name?: string; name_value?: string }>;
    if (!Array.isArray(rows)) throw new Error("invalid CT response");
    const now = Date.now();
    const active = rows.filter((row) => {
      const expiry = Date.parse(row.not_after ?? "");
      return Number.isFinite(expiry) && expiry > now;
    });
    const latest = active
      .map((row) => row.not_after ?? "")
      .filter(Boolean)
      .sort((left, right) => Date.parse(right) - Date.parse(left))[0] ?? null;
    const names = unique(active.flatMap((row) => (row.name_value ?? "").split(/\r?\n/)).map((name) => name.replace(/^\*\./, "").toLowerCase())).slice(0, 8);
    const issuer = issuerLabel(active[0]?.issuer_name);
    const found = active.length > 0;
    const detail = found
      ? `${active.length} active public certificate record${active.length === 1 ? "" : "s"} were observed. A certificate does not prove that a site is trustworthy.`
      : "No active public Certificate Transparency record was found. This does not by itself prove that HTTPS is invalid.";
    return {
      intelligence: {
        state: found ? "clear" : "warning",
        source: "Certificate Transparency",
        recordCount: rows.length,
        activeRecordCount: active.length,
        latestExpiry: latest ? new Date(latest).toISOString() : null,
        issuer,
        names,
      },
      provider: { name: "Certificate Transparency", state: found ? "clear" : "warning", label: found ? "Active record" : "No active record", detail, configured: true },
      riskBoost: found ? 0 : 6,
      reason: found ? null : "No active public Certificate Transparency record was observed for this HTTPS domain.",
    };
   } catch {
    const detail = "Public certificate records could not be retrieved within the safety limit.";
    return {
      intelligence: { state: "unavailable", source: "Certificate Transparency", recordCount: 0, activeRecordCount: 0, latestExpiry: null, issuer: null, names: [] },
      provider: { name: "Certificate Transparency", state: "unavailable", label: "Unavailable", detail, configured: true },
      riskBoost: 0,
      reason: null,
    };
   }
  }, ctx);
}

function isPrivateOrReservedAddress(hostname: string): boolean {
  const value = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const ipv4 = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)?.slice(1).map(Number);
  if (ipv4?.length === 4 && ipv4.every((part) => part >= 0 && part <= 255)) {
    const [a, b, c] = ipv4;
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0)
      || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113);
  }
  if (!value.includes(":")) return false;
  if (value === "::" || value === "::1") return true;
  if (/^(?:fc|fd|fe8|fe9|fea|feb)/i.test(value)) return true;
  const mapped = value.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/)?.[1];
  return mapped ? isPrivateOrReservedAddress(mapped) : false;
}

function redirectTargetBlockReason(url: URL, dns: DnsLookup) {
  if (!["http:", "https:"].includes(url.protocol)) return "The redirect uses an unsupported protocol.";
  if (url.username || url.password) return "The redirect contains embedded credentials.";
  const hostname = url.hostname.toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || isPrivateOrReservedAddress(hostname)) {
    return "The redirect points to a local or reserved destination.";
  }
  if (dns.state === "unavailable") return "The redirect destination could not be resolved safely.";
  if (!dns.addresses.length && !dns.ipv6.length) return "The redirect destination has no verified public address.";
  if ([...dns.addresses, ...dns.ipv6].some(isPrivateOrReservedAddress)) return "DNS resolved the redirect destination to a private or reserved address.";
  return null;
}

async function inspectRedirects(
  url: string,
  mode: "quick" | "deep",
  disabled: boolean,
  protectedReason?: string | null,
  initialDns?: Promise<DnsLookup>,
  ctx?: AnalysisOptions["ctx"],
): Promise<{
  intelligence: DomainIntelligence["redirects"];
  provider: DomainIntelProvider;
  riskBoost: number;
  riskFloor: number;
  reasons: string[];
}> {
  if (protectedReason) {
    return {
      intelligence: { state: "not-run", checked: false, count: 0, chain: [], finalUrl: url, crossedDomains: false, bodyFetched: false, detail: protectedReason },
      provider: { name: "Redirect path", state: "not-run", label: "Protected", detail: protectedReason, configured: true },
      riskBoost: 0,
      riskFloor: 0,
      reasons: [],
    };
  }
  if (mode !== "deep") {
    const detail = "Run Deep Scan to inspect redirect headers without rendering page content.";
    return {
      intelligence: { state: "not-run", checked: false, count: 0, chain: [], finalUrl: url, crossedDomains: false, bodyFetched: false, detail },
      provider: { name: "Redirect path", state: "not-run", label: "Deep Scan only", detail, configured: true },
      riskBoost: 0,
      riskFloor: 0,
      reasons: [],
    };
  }
  if (disabled) {
    const detail = "No redirect was observed in deterministic test mode. Page content was not fetched or rendered.";
    return {
      intelligence: { state: "clear", checked: true, count: 0, chain: [], finalUrl: url, crossedDomains: false, bodyFetched: false, detail },
      provider: { name: "Redirect path", state: "clear", label: "Direct", detail, configured: true },
      riskBoost: 0,
      riskFloor: 0,
      reasons: [],
    };
  }

  const chain: Array<{ url: string; domain: string; status: number }> = [];
  const start = new URL(url);
  let current = start;
  let crossedDomains = false;
  let downgrade = false;
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      const dns = hop === 0 && initialDns ? await initialDns : await lookupDns(current.hostname, false, ctx);
      const blocked = redirectTargetBlockReason(current, dns);
      if (blocked) {
        const detail = `${blocked} The destination was not contacted.`;
        return {
          intelligence: { state: "danger", checked: true, count: chain.length, chain, finalUrl: current.href, crossedDomains, bodyFetched: false, detail },
          provider: { name: "Redirect path", state: "danger", label: "Blocked target", detail, configured: true },
          riskBoost: 30,
          riskFloor: 72,
          reasons: [blocked],
        };
      }
      const response = await fetchWithTimeout(current, {
        method: "HEAD",
        redirect: "manual",
        headers: { accept: "*/*", "user-agent": "ScamShield-LinkInspector/2.0" },
      });
      if (response.body) await response.body.cancel().catch(() => undefined);
      const location = response.headers.get("location");
      if (response.status < 300 || response.status >= 400 || !location) {
        const state: DomainIntelState = downgrade ? "danger" : crossedDomains || chain.length >= 3 ? "warning" : "clear";
        const detail = chain.length
          ? `${chain.length} redirect${chain.length === 1 ? "" : "s"} led to ${current.hostname}. Page content was not fetched or rendered.`
          : "No redirect was observed. Page content was not fetched or rendered.";
        return {
          intelligence: { state, checked: true, count: chain.length, chain, finalUrl: current.href, crossedDomains, bodyFetched: false, detail },
          provider: { name: "Redirect path", state, label: downgrade ? "HTTPS downgrade" : crossedDomains ? "Domain changed" : chain.length ? `${chain.length} redirect${chain.length === 1 ? "" : "s"}` : "Direct", detail, configured: true },
          riskBoost: downgrade ? 28 : crossedDomains ? 12 : chain.length >= 3 ? 7 : 0,
          riskFloor: downgrade ? 72 : 0,
          reasons: downgrade
            ? ["The redirect chain downgrades from HTTPS to unencrypted HTTP."]
            : crossedDomains ? ["The URL redirects to a different destination domain."] : [],
        };
      }
      if (hop === MAX_REDIRECTS) {
        const detail = `The redirect chain exceeded the ${MAX_REDIRECTS}-hop safety limit. Page content was not fetched or rendered.`;
        return {
          intelligence: { state: "warning", checked: true, count: chain.length, chain, finalUrl: current.href, crossedDomains, bodyFetched: false, detail },
          provider: { name: "Redirect path", state: "warning", label: "Long chain", detail, configured: true },
          riskBoost: 10,
          riskFloor: 0,
          reasons: ["The URL uses a redirect chain longer than the inspection safety limit."],
        };
      }
      const next = new URL(location, current);
      if (current.protocol === "https:" && next.protocol === "http:") downgrade = true;
      if (hostnameWithoutWww(next.hostname) !== hostnameWithoutWww(current.hostname)) crossedDomains = true;
      chain.push({ url: current.href, domain: current.hostname, status: response.status });
      current = next;
    }
  } catch {
    const detail = "Redirect headers could not be inspected within the safety limit. Page content was not fetched or rendered.";
    return {
      intelligence: { state: "unavailable", checked: true, count: chain.length, chain, finalUrl: current.href, crossedDomains, bodyFetched: false, detail },
      provider: { name: "Redirect path", state: "unavailable", label: "Unavailable", detail, configured: true },
      riskBoost: 0,
      riskFloor: 0,
      reasons: [],
    };
  }
  throw new Error("unreachable redirect state");
}

export async function analyzeDomainIntelligence(
  url: string,
  mode: "quick" | "deep",
  options: AnalysisOptions,
): Promise<DomainIntelligenceResult> {
  const parsed = new URL(url);
  const domain = hostnameWithoutWww(parsed.hostname);
  const brand = inspectBrand(domain);
  const protectedReason = options.protectedReason ?? null;

  const dnsPromise = protectedReason
    ? Promise.resolve<DnsLookup>({
        state: "not-run", addresses: [], ipv6: [], nameservers: [], mailServers: [], cname: null, minTtl: null,
        dnssecAuthenticated: null, detail: protectedReason,
      })
    : lookupDns(domain, options.externalDisabled, options.ctx);
  const certificatePromise = protectedReason
    ? Promise.resolve({
        intelligence: { state: "not-run" as const, source: "Certificate Transparency" as const, recordCount: 0, activeRecordCount: 0, latestExpiry: null, issuer: null, names: [] },
        provider: { name: "Certificate Transparency", state: "not-run" as const, label: "Protected", detail: protectedReason, configured: true },
        riskBoost: 0,
        reason: null,
      })
    : inspectCertificate(domain, parsed.protocol === "https:", options.externalDisabled, options.ctx);
  const redirectsPromise = inspectRedirects(url, mode, options.externalDisabled, protectedReason, dnsPromise, options.ctx);
  const [dns, certificate, redirects] = await Promise.all([dnsPromise, certificatePromise, redirectsPromise]);

  const dnsProvider: DomainIntelProvider = {
    name: "DNS footprint",
    state: dns.state,
    label: dns.state === "clear" ? "Resolved" : dns.state === "warning" ? "No address" : dns.state === "not-run" ? "Protected" : "Unavailable",
    detail: dns.detail,
    configured: true,
  };
  const brandDetail = brand.isTyposquat && brand.suspectedBrand && brand.officialDomain
    ? `${brand.similarity}% similarity to ${brand.suspectedBrand}. The official domain is ${brand.officialDomain}.`
    : brand.officialDomain
      ? `This is an official ${brand.suspectedBrand} domain or subdomain.`
      : "No close match to a monitored brand domain was found.";
  const brandProvider: DomainIntelProvider = {
    name: "Brand similarity",
    state: brand.state,
    label: brand.state === "danger" ? "Likely impersonation" : brand.state === "warning" ? "Look-alike" : "No close match",
    detail: brandDetail,
    configured: true,
  };

  const reasons: string[] = [];
  let riskBoost = 0;
  let riskFloor = redirects.riskFloor;
  if (brand.state === "danger" && brand.suspectedBrand && brand.officialDomain) {
    reasons.push(`The domain closely imitates ${brand.suspectedBrand}; its official domain is ${brand.officialDomain}.`);
    riskBoost += 38;
    riskFloor = Math.max(riskFloor, 72);
  } else if (brand.state === "warning" && brand.suspectedBrand) {
    reasons.push(`The domain resembles ${brand.suspectedBrand} and should be verified independently.`);
    riskBoost += 20;
  }
  if (dns.state === "warning") {
    reasons.push("No public address record was returned for the destination domain.");
    riskBoost += 10;
  }
  riskBoost += certificate.riskBoost + redirects.riskBoost;
  if (certificate.reason) reasons.push(certificate.reason);
  reasons.push(...redirects.reasons);

  return {
    intelligence: {
      brand,
      dns: {
        state: dns.state,
        addresses: dns.addresses,
        ipv6: dns.ipv6,
        nameservers: dns.nameservers,
        mailServers: dns.mailServers,
        cname: dns.cname,
        minTtl: dns.minTtl,
        dnssecAuthenticated: dns.dnssecAuthenticated,
      },
      certificate: certificate.intelligence,
      redirects: redirects.intelligence,
    },
    providers: [brandProvider, dnsProvider, certificate.provider, redirects.provider],
    riskBoost,
    riskFloor,
    reasons,
  };
}
