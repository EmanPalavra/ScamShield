export type RiskLevel = "Low" | "Medium" | "High";
export type ProviderState = "clear" | "warning" | "danger" | "unavailable" | "not-run";
export type AnalystTab = "Evidence" | "URLs" | "Providers" | "IOCs";

export interface Provider {
  name: string;
  state: ProviderState;
  label: string;
  detail: string;
  configured: boolean;
  subject?: string;
}

export interface LinkReport {
  url: string;
  domain: string;
  riskScore: number;
  reasons: string[];
  providers: Provider[];
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
  domainIntelligence: {
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
      state: ProviderState;
      addresses: string[];
      ipv6: string[];
      nameservers: string[];
      mailServers: string[];
      cname: string | null;
      minTtl: number | null;
      dnssecAuthenticated: boolean | null;
    };
    certificate: {
      state: ProviderState;
      source: "Certificate Transparency";
      recordCount: number;
      activeRecordCount: number;
      latestExpiry: string | null;
      issuer: string | null;
      names: string[];
    };
    redirects: {
      state: ProviderState;
      checked: boolean;
      count: number;
      chain: Array<{ url: string; domain: string; status: number }>;
      finalUrl: string;
      crossedDomains: boolean;
      bodyFetched: false;
      detail: string;
    };
  };
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

export interface ScanResult {
  scanMode: "quick" | "deep";
  scannedAt: string;
  riskPercent: number;
  riskLevel: RiskLevel;
  riskLabel: string;
  scamType: string;
  reasons: string[];
  actions: string[];
  evidence: Array<{ source: string; impact: string; detail: string }>;
  links: LinkReport[];
  providers: Provider[];
  iocs: {
    urls: string[];
    domains: string[];
    emails: string[];
    phones: string[];
    cryptoWallets: string[];
  };
  privacy: {
    sensitiveUrlDetected: boolean;
    fullSensitiveUrlsShared: number;
    sanitizedUrls: number;
  };
  analysis: {
    inputType: "Message" | "URL" | "Message + URL";
    rulesEvaluated: number;
    messageStats: {
      characters: number;
      words: number;
      lines: number;
      uppercaseWords: number;
      exclamations: number;
    };
    signals: Array<{
      name: string;
      count: number;
      state: "clear" | "warning" | "danger";
      detail: string;
    }>;
    categoryMatches: Array<{ type: string; score: number; hits: number }>;
    providerCoverage: {
      total: number;
      completed: number;
      threats: number;
      warnings: number;
      unavailable: number;
      notRun: number;
    };
    timing: {
      localAnalysisMs: number;
      liveChecksMs: number;
      totalMs: number;
    };
    detectedLanguage: string;
  };
  deepScan: {
    checkedExistingReport: boolean;
    canSubmitFreshAnalysis: boolean;
    urls: string[];
    privacyNotice: string;
    timingNotice: string;
  };
  limits: { maxUrls: number; truncatedUrls: boolean };
}

export interface RuntimeConfig {
  turnstileSiteKey: string | null;
  turnstileConfigured: boolean;
}

export interface DeepJob {
  analysisId: string;
  statusToken: string;
  url: string;
  status: string;
  completed: boolean;
  stats: Record<string, number> | null;
  verdict: string | null;
  riskState: string;
  startedAt: number;
  pollCount: number;
  engineCount: number;
  analyzedAt: number | null;
  error?: string;
}
