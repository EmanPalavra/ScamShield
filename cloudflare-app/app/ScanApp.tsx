"use client";

import type { CSSProperties, FormEvent } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { ScamShieldLogoMark, SiteFooter, SiteHeader } from "./site-chrome";
import { useLanguage } from "./i18n";
import { exampleMessages } from "./translations";

type RiskLevel = "Low" | "Medium" | "High";
type ProviderState = "clear" | "warning" | "danger" | "unavailable" | "not-run";
type AnalystTab = "Evidence" | "URLs" | "Providers" | "IOCs";

interface Provider {
  name: string;
  state: ProviderState;
  label: string;
  detail: string;
  configured: boolean;
  subject?: string;
}

interface LinkReport {
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

interface ScanResult {
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

interface RuntimeConfig {
  turnstileSiteKey: string | null;
  turnstileConfigured: boolean;
}

interface DeepJob {
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

declare global {
  interface Window {
    turnstile?: {
      render: (
        container: HTMLElement,
        options: {
          sitekey: string;
          theme: string;
          size: string;
          callback: (token: string) => void;
          action: string;
          "expired-callback": () => void;
          "error-callback": () => void;
        },
      ) => string;
      reset: (widgetId?: string) => void;
      remove: (widgetId: string) => void;
    };
  }
}

const analystTabs: AnalystTab[] = ["Evidence", "URLs", "Providers", "IOCs"];
function riskIcon(level: RiskLevel) {
  if (level === "High") return "×";
  if (level === "Medium") return "!";
  return "✓";
}

function providerIcon(state: ProviderState) {
  if (state === "danger") return "×";
  if (state === "warning") return "!";
  if (state === "clear") return "✓";
  return "—";
}

function formatDuration(milliseconds: number) {
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  return `${(milliseconds / 1_000).toFixed(milliseconds < 10_000 ? 1 : 0)} s`;
}

function formatDomainAge(days: number | null) {
  if (days === null) return "Age unavailable";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} old`;
  if (days < 730) return `${Math.round(days / 30)} months old`;
  return `${(days / 365).toFixed(1)} years old`;
}

function wait(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("Polling cancelled", "AbortError"));
      return;
    }
    const onAbort = () => {
      window.clearTimeout(timer);
      reject(new DOMException("Polling cancelled", "AbortError"));
    };
    const timer = window.setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export function ScanApp() {
  const { locale, t } = useLanguage();
  const [message, setMessage] = useState("");
  const [view, setView] = useState<"simple" | "analyst">("simple");
  const [activeTab, setActiveTab] = useState<AnalystTab>("Evidence");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loadingMode, setLoadingMode] = useState<"quick" | "deep" | null>(null);
  const [progressStep, setProgressStep] = useState(0);
  const [error, setError] = useState("");
  const [copyLabel, setCopyLabel] = useState("Copy report");
  const [config, setConfig] = useState<RuntimeConfig | null>(null);
  const [turnstileToken, setTurnstileToken] = useState("");
  const [consent, setConsent] = useState(false);
  const [selectedDeepUrl, setSelectedDeepUrl] = useState("");
  const [deepJob, setDeepJob] = useState<DeepJob | null>(null);
  const [deepSubmitting, setDeepSubmitting] = useState(false);
  const [deepTracking, setDeepTracking] = useState(false);
  const [deepElapsedSeconds, setDeepElapsedSeconds] = useState(0);
  const turnstileContainer = useRef<HTMLDivElement>(null);
  const turnstileWidgetId = useRef<string | null>(null);
  const resultsRef = useRef<HTMLElement>(null);
  const deepPollController = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const loadConfig = async () => {
      try {
        const response = await fetch("/api/config", { signal: controller.signal });
        if (!response.ok) throw new Error("Runtime configuration is unavailable.");
        setConfig((await response.json()) as RuntimeConfig);
      } catch (configError) {
        if (!(configError instanceof DOMException && configError.name === "AbortError")) {
          setConfig(null);
        }
      }
    };
    void loadConfig();
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!config?.turnstileConfigured || !config.turnstileSiteKey || !turnstileContainer.current) return;

    const renderWidget = () => {
      if (!window.turnstile || !turnstileContainer.current || turnstileWidgetId.current) return;
      turnstileWidgetId.current = window.turnstile.render(turnstileContainer.current, {
        sitekey: config.turnstileSiteKey ?? "",
        theme: "auto",
        size: "flexible",
        action: "turnstile-spin-v2",
        callback: (token) => setTurnstileToken(token),
        "expired-callback": () => setTurnstileToken(""),
        "error-callback": () => setTurnstileToken(""),
      });
    };

    const existing = document.getElementById("cloudflare-turnstile-script") as HTMLScriptElement | null;
    if (existing) {
      if (window.turnstile) renderWidget();
      else existing.addEventListener("load", renderWidget, { once: true });
      return;
    }

    const script = document.createElement("script");
    script.id = "cloudflare-turnstile-script";
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.addEventListener("load", renderWidget, { once: true });
    document.head.appendChild(script);
  }, [config]);

  useEffect(() => () => deepPollController.current?.abort(), []);

  useEffect(() => {
    if (!deepJob || deepJob.completed) return;
    const updateElapsed = () => setDeepElapsedSeconds(Math.max(0, Math.floor((Date.now() - deepJob.startedAt) / 1_000)));
    updateElapsed();
    const timer = window.setInterval(updateElapsed, 1_000);
    return () => window.clearInterval(timer);
  }, [deepJob]);

  const progressLabels = useMemo(() => {
    const base = ["Analyzing message", "Checking domain", "Checking reputation providers"];
    if (loadingMode === "deep") base.push("Checking existing VirusTotal report");
    return base;
  }, [loadingMode]);

  useEffect(() => {
    if (!loadingMode) return;
    setProgressStep(0);
    const timer = window.setInterval(() => {
      setProgressStep((current) => Math.min(current + 1, progressLabels.length - 1));
    }, 700);
    return () => window.clearInterval(timer);
  }, [loadingMode, progressLabels.length]);

  function resetTurnstile() {
    setTurnstileToken("");
    if (window.turnstile && turnstileWidgetId.current) window.turnstile.reset(turnstileWidgetId.current);
  }

  function clearAll() {
    deepPollController.current?.abort();
    deepPollController.current = null;
    setMessage("");
    setResult(null);
    setError("");
    setConsent(false);
    setSelectedDeepUrl("");
    setDeepJob(null);
    setDeepTracking(false);
    setDeepElapsedSeconds(0);
    setProgressStep(0);
    resetTurnstile();
  }

  async function runScan(mode: "quick" | "deep") {
    const clean = message.trim();
    if (!clean) {
      setError("Paste a message or link before starting a scan.");
      return;
    }
    if (config?.turnstileConfigured && !turnstileToken) {
      setError("Complete the human verification before scanning.");
      return;
    }

    deepPollController.current?.abort();
    deepPollController.current = null;
    setDeepTracking(false);
    setDeepElapsedSeconds(0);
    setLoadingMode(mode);
    setError("");
    setResult(null);
    setConsent(false);
    setDeepJob(null);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ message: clean, mode, turnstileToken }),
      });
      const payload = (await response.json()) as ScanResult & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "The scan could not be completed.");
      setResult(payload);
      setSelectedDeepUrl(payload.deepScan.urls[0] ?? "");
      window.setTimeout(() => resultsRef.current?.focus({ preventScroll: false }), 60);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "The scan could not be completed.");
    } finally {
      setLoadingMode(null);
      resetTurnstile();
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runScan("quick");
  }

  async function copyReport() {
    if (!result) return;
    const report = [
      `ScamShield report — ${result.riskLevel} risk (${result.riskPercent}%)`,
      `Assessment: ${result.riskLabel}`,
      `Pattern: ${result.scamType}`,
      "",
      "Key reasons:",
      ...result.reasons.map((reason) => `- ${reason}`),
      "",
      "Recommended actions:",
      ...result.actions.map((action) => `- ${action}`),
      "",
      `Input: ${result.analysis.inputType}`,
      `Rules evaluated: ${result.analysis.rulesEvaluated}`,
      `Provider checks: ${result.analysis.providerCoverage.completed}/${result.analysis.providerCoverage.total} completed`,
      `Scan time: ${formatDuration(result.analysis.timing.totalMs)}`,
      "",
      `Scanned: ${new Date(result.scannedAt).toLocaleString()}`,
      "This is a risk estimate, not a guarantee.",
    ].join("\n");
    try {
      await navigator.clipboard.writeText(report);
      setCopyLabel("Copied");
      window.setTimeout(() => setCopyLabel("Copy report"), 1_500);
    } catch {
      setCopyLabel("Copy failed");
    }
  }

  async function pollDeepAnalysis(analysisId: string, statusToken: string, url: string, startedAt = Date.now()) {
    deepPollController.current?.abort();
    const controller = new AbortController();
    deepPollController.current = controller;
    setDeepTracking(true);
    setDeepElapsedSeconds(Math.max(0, Math.floor((Date.now() - startedAt) / 1_000)));

    let nextDelay = 350;
    try {
      for (let attempt = 0; attempt < 18; attempt += 1) {
        await wait(nextDelay, controller.signal);
        const response = await fetch(`/api/deep/status?id=${encodeURIComponent(analysisId)}`, {
          signal: controller.signal,
          headers: { "x-scamshield-status-token": statusToken },
        });
        const payload = (await response.json()) as Partial<DeepJob> & { error?: string; pollAfterMs?: number };

        if (!response.ok) {
          if (response.status === 429) {
            nextDelay = Math.max(2_000, Number(response.headers.get("retry-after") ?? 2) * 1_000);
            continue;
          }
          throw new Error(payload.error ?? "Analysis status could not be retrieved.");
        }

        const nextJob: DeepJob = {
          analysisId,
          statusToken,
          url,
          status: payload.status ?? "queued",
          completed: payload.completed === true,
          stats: payload.stats ?? null,
          verdict: payload.verdict ?? null,
          riskState: payload.riskState ?? "pending",
          startedAt,
          pollCount: attempt + 1,
          engineCount: payload.engineCount ?? 0,
          analyzedAt: payload.analyzedAt ?? null,
        };
        setDeepJob(nextJob);
        if (nextJob.completed) return;
        nextDelay = Math.min(2_500, payload.pollAfterMs ?? 700 + attempt * 180);
      }

      setDeepJob((current) => current ? {
        ...current,
        error: "VirusTotal is still processing this URL. Use Check status to continue without resubmitting it.",
      } : null);
    } catch (pollError) {
      if (pollError instanceof DOMException && pollError.name === "AbortError") return;
      setDeepJob((current) => ({
        analysisId,
        statusToken,
        url,
        status: current?.status ?? "queued",
        completed: false,
        stats: current?.stats ?? null,
        verdict: current?.verdict ?? null,
        riskState: current?.riskState ?? "pending",
        startedAt: current?.startedAt ?? startedAt,
        pollCount: current?.pollCount ?? 0,
        engineCount: current?.engineCount ?? 0,
        analyzedAt: current?.analyzedAt ?? null,
        error: pollError instanceof Error ? pollError.message : "Analysis tracking failed.",
      }));
    } finally {
      if (deepPollController.current === controller) deepPollController.current = null;
      setDeepTracking(false);
    }
  }

  async function submitFreshAnalysis() {
    if (!selectedDeepUrl || !consent) {
      setError("Choose a URL and confirm the VirusTotal privacy notice first.");
      return;
    }
    if (config?.turnstileConfigured && !turnstileToken) {
      setError("Complete the new human verification before submitting the URL.");
      return;
    }

    setDeepSubmitting(true);
    setError("");
    try {
      const response = await fetch("/api/deep/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: selectedDeepUrl, consent: true, turnstileToken }),
      });
      const payload = (await response.json()) as { analysisId?: string; statusToken?: string; url?: string; status?: string; error?: string };
      if (!response.ok || !payload.analysisId || !payload.statusToken) throw new Error(payload.error ?? "Fresh analysis could not be started.");
      const job: DeepJob = {
        analysisId: payload.analysisId,
        statusToken: payload.statusToken,
        url: payload.url ?? selectedDeepUrl,
        status: payload.status ?? "queued",
        completed: false,
        stats: null,
        verdict: null,
        riskState: "pending",
        startedAt: Date.now(),
        pollCount: 0,
        engineCount: 0,
        analyzedAt: null,
      };
      setDeepJob(job);
      resetTurnstile();
      void pollDeepAnalysis(job.analysisId, job.statusToken, job.url, job.startedAt);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Fresh analysis could not be started.");
    } finally {
      setDeepSubmitting(false);
    }
  }

  function refreshDeepAnalysis() {
    if (!deepJob || deepTracking) return;
    setDeepJob({ ...deepJob, error: undefined });
    void pollDeepAnalysis(deepJob.analysisId, deepJob.statusToken, deepJob.url, deepJob.startedAt);
  }

  const detectedSignals = result?.analysis.signals.filter((signal) => signal.count > 0).length ?? 0;
  const resultHeadline = result?.riskLevel === "High"
    ? "Do not interact with this message"
    : result?.riskLevel === "Medium"
      ? "Verify this before taking action"
      : "No strong threat was confirmed";

  return (
    <>
      <SiteHeader />
      <main>
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-copy">
            <div className="hero-badge"><span aria-hidden="true" /> Live threat triage</div>
            <h1 id="hero-title">See the risk.<br /><span>Understand why.</span></h1>
            <p className="hero-lead">
              Paste a suspicious message or link. ScamShield turns message signals, URL structure, and live threat intelligence into one clear, explainable decision.
            </p>
            <div className="trust-row" aria-label="Service qualities">
              <span><b aria-hidden="true">✓</b> No account required</span>
              <span><b aria-hidden="true">✓</b> Links are never opened</span>
              <span><b aria-hidden="true">✓</b> Fresh scans require consent</span>
            </div>
          </div>

          <aside className="hero-console" aria-label="ScamShield protection layers">
            <div className="console-topline">
              <span><i aria-hidden="true" /> Protection stack</span>
              <b>ONLINE</b>
            </div>
            <div className="shield-orbit" aria-hidden="true">
              <span className="orbit orbit-one" />
              <span className="orbit orbit-two" />
              <div className="hero-shield"><ScamShieldLogoMark /></div>
            </div>
            <div className="console-layers">
              <div><span>01</span><p><strong>Language</strong><small>Social-engineering signals</small></p><b>ACTIVE</b></div>
              <div><span>02</span><p><strong>Link intelligence</strong><small>Structure, age & reputation</small></p><b>ACTIVE</b></div>
              <div><span>03</span><p><strong>Decision layer</strong><small>Explainable risk score</small></p><b>READY</b></div>
            </div>
          </aside>
        </section>

        <section className="scanner-shell" aria-labelledby="scanner-title">
          <div className="scanner-heading">
            <div>
              <p className="section-kicker">Security workspace</p>
              <h2 id="scanner-title">Analyze a message or URL</h2>
              <p className="scanner-intro">Use the complete message for a more accurate result. ScamShield analyzes context without visiting suspicious destinations.</p>
            </div>
            <div className="privacy-chip"><span aria-hidden="true">◆</span><div><strong>Private by default</strong><small>Processed only for this scan</small></div></div>
          </div>

          <form onSubmit={onSubmit}>
            <div className="editor-card">
              <div className="editor-toolbar">
                <label htmlFor="message">Message or link</label>
                <span>{message.length.toLocaleString()} / 10,000</span>
              </div>
              <textarea
                id="message"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                maxLength={10_000}
                placeholder="Paste the full SMS, email, chat message, or suspicious URL here…"
                rows={8}
                disabled={Boolean(loadingMode)}
              />
              <div className="field-footer">
                <span><b aria-hidden="true">!</b> Remove passwords, one-time codes, and private internal links.</span>
                <button type="button" className="text-button" onClick={() => { setMessage(exampleMessages[locale]); setError(""); }}>Load safe example</button>
              </div>
            </div>

            {config?.turnstileConfigured ? (
              <div className="turnstile-wrap" aria-label="Human verification"><div ref={turnstileContainer} /></div>
            ) : (
              <div className="protection-status">
                <span aria-hidden="true">✓</span>
                <p><strong>Abuse protection is active.</strong> Request limits protect the scanner; Turnstile appears automatically when production keys are connected.</p>
              </div>
            )}

            {error && <div className="error-banner" role="alert"><span aria-hidden="true">!</span>{error}</div>}

            <div className="scan-options" aria-label="Choose scan depth">
              <button className="scan-option quick-option" type="submit" disabled={Boolean(loadingMode)}>
                <span className="mode-icon" aria-hidden="true">Q</span>
                <span className="mode-copy">
                  <span className="mode-title"><strong>Quick Scan</strong><em>Recommended</em></span>
                  <small>Fast decision using message signals, URL structure, Google Safe Browsing, and domain age.</small>
                  <span className="mode-features"><b>Message</b><b>URL</b><b>Live reputation</b></span>
                </span>
                <span className="mode-arrow" aria-hidden="true">→</span>
              </button>
              <button className="scan-option deep-option" type="button" onClick={() => void runScan("deep")} disabled={Boolean(loadingMode)}>
                <span className="mode-icon" aria-hidden="true">D</span>
                <span className="mode-copy">
                  <span className="mode-title"><strong>Deep Scan</strong><em>More intelligence</em></span>
                  <small>Adds the latest existing VirusTotal report. It does not submit a new URL without your consent.</small>
                  <span className="mode-features"><b>Everything in Quick</b><b>VirusTotal history</b></span>
                </span>
                <span className="mode-arrow" aria-hidden="true">→</span>
              </button>
            </div>

            <div className="utility-actions">
              <span>Quick Scan is enough for most messages. Use Deep Scan when a link is the main concern.</span>
              <button type="button" className="text-button" onClick={clearAll}>Clear workspace</button>
            </div>
          </form>

          {loadingMode && (
            <div className="progress-panel" role="status" aria-live="polite">
              <div className="progress-heading">
                <span className="scanner-pulse" aria-hidden="true"><i /><i /><i /></span>
                <div><strong>{loadingMode === "deep" ? "Running full intelligence scan" : "Running rapid risk scan"}</strong><p>Your result will appear here as soon as the slowest live provider responds.</p></div>
                <b>{Math.round(((progressStep + 1) / progressLabels.length) * 100)}%</b>
              </div>
              <ol>
                {progressLabels.map((label, index) => (
                  <li key={label} className={index < progressStep ? "done" : index === progressStep ? "active" : ""}>
                    <span aria-hidden="true">{index < progressStep ? "✓" : String(index + 1).padStart(2, "0")}</span><p>{label}</p>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </section>

        {result && (
          <section className={`results risk-${result.riskLevel.toLowerCase()}`} ref={resultsRef} tabIndex={-1} aria-labelledby="result-title">
            <div className="results-topline">
              <div>
                <p className="section-kicker">{result.scanMode === "deep" ? "Deep intelligence report" : "Rapid risk report"}</p>
                <h2 id="result-title">{t(resultHeadline)}</h2>
              </div>
              <div className="result-actions">
                <div className="view-switch" aria-label="Result detail level">
                  <button type="button" className={view === "simple" ? "active" : ""} onClick={() => setView("simple")} aria-pressed={view === "simple"}>Overview</button>
                  <button type="button" className={view === "analyst" ? "active" : ""} onClick={() => setView("analyst")} aria-pressed={view === "analyst"}>Technical</button>
                </div>
                <button className="copy-button" type="button" onClick={() => void copyReport()}>{copyLabel}</button>
              </div>
            </div>

            <div className="result-summary">
              <div className="risk-gauge-shell">
                <div
                  className="risk-visual"
                  style={{ "--risk-progress": `${result.riskPercent * 3.6}deg` } as CSSProperties}
                  aria-label={`${t(result.riskLevel)} ${t("risk")}, ${result.riskPercent} percent`}
                >
                  <div><span className="risk-symbol" aria-hidden="true">{riskIcon(result.riskLevel)}</span><span className="risk-score-value"><strong>{result.riskPercent}</strong><small>/100</small></span></div>
                </div>
                <span>{t(result.riskLevel)} {t("risk")}</span>
              </div>
              <div className="risk-copy">
                <span className="risk-pill">{t(result.riskLabel)}</span>
                <h3>{t(result.scamType)}</h3>
                <p>
                  {t(result.riskLevel === "High"
                    ? "Multiple strong warning signals were found. Treat the content as unsafe until you verify it through an official channel."
                    : result.riskLevel === "Medium"
                      ? "The message contains signals that deserve independent verification before you reply, click, pay, or share information."
                      : "No strong threat was confirmed, but reputation sources cannot guarantee that a new or targeted scam is safe.")}
                </p>
                <div className="verdict-command"><span>Recommended now</span><strong>{t(result.actions[0])}</strong></div>
              </div>
            </div>

            <div className="result-metrics" aria-label="Scan coverage summary">
              <article><span>Input analyzed</span><strong>{t(result.analysis.inputType)}</strong><small>{t(result.analysis.detectedLanguage)} · {result.analysis.messageStats.words} {t("words")} · {result.analysis.messageStats.characters} {t("characters")}</small></article>
              <article><span>Signals found</span><strong>{detectedSignals} / {result.analysis.signals.length}</strong><small>{t(`${result.analysis.rulesEvaluated} detection rules evaluated`)}</small></article>
              <article><span>Live coverage</span><strong>{result.analysis.providerCoverage.completed} / {result.analysis.providerCoverage.total}</strong><small>{t(`${result.analysis.providerCoverage.threats} threat · ${result.analysis.providerCoverage.warnings} warning`)}</small></article>
              <article><span>Completed in</span><strong>{formatDuration(result.analysis.timing.totalMs)}</strong><small>{t(`${result.links.length} URL${result.links.length === 1 ? "" : "s"} inspected`)}</small></article>
            </div>

            {result.limits.truncatedUrls && <div className="coverage-warning" role="note">Only the first {result.limits.maxUrls} URLs were inspected. Remove extra links and scan again if you need the others checked.</div>}

            {view === "simple" ? (
              <div className="simple-dashboard">
                <div className="simple-grid">
                  <article className="result-list-card findings-card">
                    <div className="card-title"><span aria-hidden="true">!</span><div><p>Why it was flagged</p><h3>Key findings</h3></div></div>
                    <ol className="finding-list">
                      {result.reasons.map((reason, index) => <li key={`${reason}-${index}`}><span>{String(index + 1).padStart(2, "0")}</span><p>{t(reason)}</p></li>)}
                    </ol>
                  </article>
                  <article className="result-list-card action-card">
                    <div className="card-title"><span aria-hidden="true">→</span><div><p>Recommended response</p><h3>What to do next</h3></div></div>
                    <ol className="action-list">
                      {result.actions.map((action, index) => <li key={action}><span>{index + 1}</span><p>{t(action)}</p></li>)}
                    </ol>
                  </article>
                </div>

                <div className="inspection-grid">
                  <article className="inspection-card">
                    <div className="inspection-head"><div><p>Message analysis</p><h3>Signals inspected</h3></div><span>{t(`${detectedSignals} detected`)}</span></div>
                    <div className="signal-list">
                      {result.analysis.signals.map((signal) => (
                        <div key={signal.name} className={`signal-row signal-${signal.state}`}>
                          <span className="signal-state" aria-hidden="true">{signal.state === "clear" ? "✓" : "!"}</span>
                          <div><strong>{t(signal.name)}</strong><p>{t(signal.detail)}</p></div>
                          <b>{signal.count || t("Clear")}</b>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="inspection-card">
                    <div className="inspection-head"><div><p>Threat intelligence</p><h3>Provider checks</h3></div><span>{t(`${result.analysis.providerCoverage.completed} completed`)}</span></div>
                    <div className="compact-providers">
                      {result.providers.map((provider, index) => (
                        <div key={`${provider.name}-${provider.subject}-${index}`} className={`compact-provider provider-${provider.state}`}>
                          <span className="provider-icon" aria-hidden="true">{providerIcon(provider.state)}</span>
                          <div><strong>{provider.name}</strong><small>{provider.subject}</small><p>{t(provider.detail)}</p></div>
                          <b>{t(provider.label)}</b>
                        </div>
                      ))}
                    </div>
                  </article>
                </div>

                <section className="url-overview" aria-labelledby="url-overview-title">
                  <div className="section-heading-row"><div><p className="section-kicker">Link intelligence</p><h3 id="url-overview-title">URLs inspected</h3></div><span>{t(`${result.links.length} total`)}</span></div>
                  {result.links.length ? result.links.map((link) => (
                    <article key={link.url} className={`url-report ${link.riskScore >= 67 ? "url-danger" : link.riskScore >= 34 ? "url-warning" : "url-clear"}`}>
                      <div className="url-report-main">
                        <div className="url-identity"><span>Destination domain</span><strong>{link.domain}</strong><code>{link.url}</code></div>
                        <div className="url-score"><strong>{link.riskScore}</strong><span>/100 link risk</span></div>
                      </div>
                      <div className="url-facts">
                        <span><b>{link.technical.protocol}</b> protocol</span>
                        <span><b>{formatDomainAge(link.domainAgeDays)}</b> registration</span>
                        <span><b>{link.technical.pathDepth}</b> path levels</span>
                        <span><b>{link.technical.queryParameters}</b> query parameters</span>
                        <span><b>{link.technical.isPunycode ? "Yes" : "No"}</b> Punycode</span>
                      </div>
                      <ul>{link.reasons.map((reason) => <li key={reason}>{t(reason)}</li>)}</ul>
                      {link.virusTotal?.found && link.virusTotal.stats && (
                        <div className="vt-inline"><span>VirusTotal existing report</span><b>{link.virusTotal.stats.malicious ?? 0} malicious</b><b>{link.virusTotal.stats.suspicious ?? 0} suspicious</b><b>{link.virusTotal.stats.harmless ?? 0} harmless</b></div>
                      )}
                    </article>
                  )) : <div className="empty-state"><strong>No link was present.</strong><p>The result is based on message language and social-engineering signals only.</p></div>}
                </section>
              </div>
            ) : (
              <div className="analyst-panel">
                <div className="analyst-tabs" role="tablist" aria-label="Technical result sections">
                  {analystTabs.map((tab) => (
                    <button key={tab} type="button" role="tab" aria-selected={activeTab === tab} className={activeTab === tab ? "active" : ""} onClick={() => setActiveTab(tab)}>{tab}</button>
                  ))}
                </div>

                {activeTab === "Evidence" && (
                  <div className="tab-content evidence-table" role="tabpanel">
                    <div className="technical-summary"><span>Local analysis <b>{formatDuration(result.analysis.timing.localAnalysisMs)}</b></span><span>Live checks <b>{formatDuration(result.analysis.timing.liveChecksMs)}</b></span><span>Rules <b>{result.analysis.rulesEvaluated}</b></span><span>Lines <b>{result.analysis.messageStats.lines}</b></span></div>
                    {result.evidence.map((item, index) => (
                      <article key={`${item.source}-${index}`}><span className={`impact impact-${item.impact.toLowerCase()}`}>{t(item.impact)}</span><div><strong>{t(item.source)}</strong><p>{t(item.detail)}</p></div></article>
                    ))}
                  </div>
                )}

                {activeTab === "URLs" && (
                  <div className="tab-content url-grid" role="tabpanel">
                    {result.links.length ? result.links.map((link) => (
                      <article key={link.url} className="url-card">
                        <div className="url-card-head"><div><span>Domain</span><strong>{link.domain}</strong></div><b>{link.riskScore}% link risk</b></div>
                        <code>{link.url}</code>
                        <div className="technical-chips"><span>{link.technical.protocol}</span><span>.{link.technical.tld}</span><span>{link.technical.hostnameLength} hostname chars</span><span>{link.technical.isShortener ? "Shortened URL" : "Direct URL"}</span><span>{link.technical.hasUserInfo ? "User-info present" : "No user-info"}</span></div>
                        <ul>{link.reasons.map((reason) => <li key={reason}>{t(reason)}</li>)}</ul>
                      </article>
                    )) : <p className="empty-state">No URL was found in this message.</p>}
                  </div>
                )}

                {activeTab === "Providers" && (
                  <div className="tab-content provider-grid" role="tabpanel">
                    {result.providers.map((provider, index) => (
                      <article key={`${provider.name}-${provider.subject}-${index}`} className={`provider-card provider-${provider.state}`}>
                        <span className="provider-icon" aria-hidden="true">{providerIcon(provider.state)}</span>
                        <div><span>{provider.subject}</span><h3>{provider.name}</h3><p>{t(provider.detail)}</p></div>
                        <b>{t(provider.label)}</b>
                      </article>
                    ))}
                  </div>
                )}

                {activeTab === "IOCs" && (
                  <div className="tab-content ioc-grid" role="tabpanel">
                    {Object.entries(result.iocs).map(([label, values]) => (
                      <article key={label}><h3>{label.replace(/([A-Z])/g, " $1")}</h3>{values.length ? values.map((value) => <code key={value}>{value}</code>) : <p>None found</p>}</article>
                    ))}
                  </div>
                )}
              </div>
            )}

            {result.scanMode === "deep" && (
              <section className="deep-panel" aria-labelledby="fresh-analysis-title">
                <div className="deep-heading">
                  <div className="deep-icon" aria-hidden="true">VT</div>
                  <div><p className="section-kicker">Optional live re-analysis</p><h3 id="fresh-analysis-title">Request a fresh VirusTotal scan</h3><p>{result.deepScan.timingNotice}</p></div>
                  <span className="external-badge">External service</span>
                </div>

                <div className="existing-report-grid">
                  {result.links.map((link) => (
                    <div key={link.url}>
                      <span>{link.domain}</span>
                      <strong>{link.virusTotal?.found ? "Existing report checked" : "No existing report"}</strong>
                      <small>{link.virusTotal?.lastAnalysisDate ? `Last analyzed ${new Date(link.virusTotal.lastAnalysisDate * 1_000).toLocaleDateString()}` : "A fresh scan is optional and requires consent."}</small>
                    </div>
                  ))}
                </div>

                {result.deepScan.canSubmitFreshAnalysis ? (
                  <div className="consent-box">
                    {result.deepScan.urls.length > 1 && (
                      <label className="select-label">URL to submit<select value={selectedDeepUrl} onChange={(event) => setSelectedDeepUrl(event.target.value)}>{result.deepScan.urls.map((url) => <option key={url} value={url}>{url}</option>)}</select></label>
                    )}
                    <div className="privacy-warning"><span aria-hidden="true">!</span><p>{result.deepScan.privacyNotice}</p></div>
                    <label className="consent-check"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><span>I understand and explicitly consent to sending this URL to VirusTotal for a new public analysis.</span></label>
                    <button className="button deep-submit" type="button" disabled={!consent || deepSubmitting || Boolean(deepJob && !deepJob.completed)} onClick={() => void submitFreshAnalysis()}>
                      {deepSubmitting ? "Sending securely…" : deepJob && !deepJob.completed ? "Analysis already submitted" : "Start fresh VirusTotal analysis"}
                    </button>
                  </div>
                ) : result.deepScan.urls.length > 0 ? <div className="provider-missing">Fresh analysis needs a VirusTotal API key in the hosted environment.</div> : <div className="empty-state">No URL was found, so a fresh URL analysis cannot be started.</div>}

                {deepJob && (
                  <div className={`deep-job job-${deepJob.riskState} ${deepJob.completed ? "job-complete" : ""}`} role="status" aria-live="polite">
                    <div className="job-topline"><div><span className={deepJob.completed ? "job-check" : "spinner"} aria-hidden="true">{deepJob.completed ? "✓" : ""}</span><div><p>VirusTotal live analysis</p><strong>{deepJob.completed ? `Complete · ${deepJob.verdict ?? "report ready"}` : deepJob.error ? "Still processing externally" : `${deepJob.status.replace(/-/g, " ")} · tracking automatically`}</strong></div></div><span>{deepJob.completed ? "DONE" : `${deepElapsedSeconds}s elapsed`}</span></div>
                    <div className="job-progress" role="progressbar" aria-label="VirusTotal analysis progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={deepJob.completed ? 100 : deepJob.status === "in-progress" ? 72 : 38}><span style={{ width: `${deepJob.completed ? 100 : deepJob.status === "in-progress" ? 72 : 38}%` }} /></div>
                    <div className="job-stages"><span className="done">Submitted</span><span className={deepJob.status === "in-progress" || deepJob.completed ? "done" : "active"}>Engine analysis</span><span className={deepJob.completed ? "done" : ""}>Final verdict</span></div>
                    {deepJob.completed && deepJob.stats ? (
                      <div className="vt-stats"><div><strong>{deepJob.stats.malicious ?? 0}</strong><span>Malicious</span></div><div><strong>{deepJob.stats.suspicious ?? 0}</strong><span>Suspicious</span></div><div><strong>{deepJob.stats.harmless ?? 0}</strong><span>Harmless</span></div><div><strong>{deepJob.stats.undetected ?? 0}</strong><span>Undetected</span></div></div>
                    ) : <p className="job-message">{deepJob.error ?? "ScamShield has already completed its own report above. VirusTotal controls this external queue; you can continue reviewing the findings while it finishes."}</p>}
                    {!deepJob.completed && !deepTracking && <button className="refresh-job" type="button" onClick={refreshDeepAnalysis}>Check status now</button>}
                  </div>
                )}
              </section>
            )}
          </section>
        )}

        <section className="method-strip" aria-label="Scan stages">
          <div><span>01</span><strong>Language signals</strong><p>Urgency, credentials, payments, impersonation, and formatting pressure.</p></div>
          <div><span>02</span><strong>URL forensics</strong><p>Domain shape, Punycode, hidden destinations, risky paths, and age.</p></div>
          <div><span>03</span><strong>Threat intelligence</strong><p>Google Safe Browsing, RDAP, and optional VirusTotal history.</p></div>
          <div><span>04</span><strong>Actionable verdict</strong><p>One clear decision, supporting evidence, and safe next steps.</p></div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}

export { SiteFooter, SiteHeader };
