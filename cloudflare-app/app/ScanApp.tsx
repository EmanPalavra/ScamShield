"use client";

import type { CSSProperties, FormEvent } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { ScamShieldLogoMark, SiteFooter, SiteHeader } from "./site-chrome";
import { DeepScanPanel } from "./scanner/DeepScanPanel";
import { useLanguage } from "./i18n";
import { exampleMessages } from "./translations";
import {
  formatDomainAge,
  formatDuration,
  providerIcon,
  riskIcon,
} from "./scanner/format";
import { findSensitiveUrlParameters } from "./scanner/sensitive-url";
import type {
  AnalystTab,
  DeepJob,
  RuntimeConfig,
  ScanResult,
} from "./scanner/types";


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
const iocLabels: Record<keyof ScanResult["iocs"], string> = {
  urls: "URLs",
  domains: "Domains",
  emails: "Email addresses",
  phones: "Phone numbers",
  cryptoWallets: "Crypto wallets",
};

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
  const [sensitiveUrlConsent, setSensitiveUrlConsent] = useState(false);
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
    if (!result || loadingMode) return;
    let positionFrame = 0;
    const layoutFrame = window.requestAnimationFrame(() => {
      positionFrame = window.requestAnimationFrame(() => {
        const target = resultsRef.current;
        if (!target) return;
        const header = document.querySelector<HTMLElement>(".site-header");
        const headerRect = header?.getBoundingClientRect();
        const stickyTop = header ? Number.parseFloat(window.getComputedStyle(header).top) || 0 : 0;
        const gap = window.innerWidth <= 720 ? 14 : 20;
        const top = window.scrollY + target.getBoundingClientRect().top - (headerRect?.height ?? 0) - stickyTop - gap;

        target.focus({ preventScroll: true });
        window.scrollTo({
          top: Math.max(0, top),
          behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
        });
      });
    });
    return () => {
      window.cancelAnimationFrame(layoutFrame);
      window.cancelAnimationFrame(positionFrame);
    };
  }, [loadingMode, result]);

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
  const sensitiveUrlParameters = useMemo(() => findSensitiveUrlParameters(message), [message]);

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
    setSensitiveUrlConsent(false);
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
        body: JSON.stringify({ message: clean, mode, turnstileToken, sensitiveUrlConsent }),
      });
      const payload = (await response.json()) as ScanResult & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "The scan could not be completed.");
      setResult(payload);
      setSelectedDeepUrl(payload.deepScan.urls[0] ?? "");
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
      `${t("ScamShield report")}: ${t(result.riskLevel)} ${t("risk")} (${result.riskPercent}%)`,
      `${t("Assessment")}: ${t(result.riskLabel)}`,
      `${t("Pattern")}: ${t(result.scamType)}`,
      "",
      `${t("Key reasons")}:`,
      ...result.reasons.map((reason) => `- ${t(reason)}`),
      "",
      `${t("Recommended actions")}:`,
      ...result.actions.map((action) => `- ${t(action)}`),
      "",
      `${t("Input")}: ${t(result.analysis.inputType)}`,
      `${t("Rules evaluated")}: ${result.analysis.rulesEvaluated}`,
      `${t("Provider checks")}: ${result.analysis.providerCoverage.completed}/${result.analysis.providerCoverage.total} ${t("completed")}`,
      `${t("Scan time")}: ${formatDuration(result.analysis.timing.totalMs)}`,
      "",
      `${t("Scanned")}: ${new Date(result.scannedAt).toLocaleString(locale)}`,
      t("This is a risk estimate, not a guarantee."),
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
        body: JSON.stringify({ url: selectedDeepUrl, consent: true, turnstileToken, sensitiveUrlConsent }),
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
  const signalGroups = result
    ? ([
        { state: "danger", label: "High-confidence signals" },
        { state: "warning", label: "Supporting warnings" },
        { state: "clear", label: "Clear or neutral signals" },
      ] as const)
        .map((group) => ({
          ...group,
          signals: result.analysis.signals.filter((signal) => signal.state === group.state),
        }))
        .filter((group) => group.signals.length > 0)
    : [];
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
              <span><b aria-hidden="true">✓</b> Page content is never rendered</span>
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
              <p className="scanner-intro">Use the complete message for a more accurate result. ScamShield analyzes context without rendering suspicious destinations.</p>
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
                onChange={(event) => {
                  setMessage(event.target.value);
                  setSensitiveUrlConsent(false);
                }}
                maxLength={10_000}
                placeholder="Paste the full SMS, email, chat message, or suspicious URL here…"
                rows={8}
                disabled={Boolean(loadingMode)}
              />
              <div className="field-footer">
                <span><b aria-hidden="true">!</b> Remove passwords, one-time codes, and private internal links.</span>
                <button type="button" className="text-button" onClick={() => { setMessage(exampleMessages[locale]); setSensitiveUrlConsent(false); setError(""); }}>Load safe example</button>
              </div>
            </div>

            {sensitiveUrlParameters.length > 0 && (
              <div className="sensitive-url-sharing" role="group" aria-labelledby="sensitive-url-title">
                <div>
                  <strong id="sensitive-url-title">Sensitive URL detected</strong>
                  <p>
                    ScamShield will remove values for {sensitiveUrlParameters.join(", ")} before external checks.
                    Enable exact sharing only if you understand that the complete URL may grant access to an account, session, or private document.
                  </p>
                </div>
                <label className="consent-check">
                  <input
                    type="checkbox"
                    checked={sensitiveUrlConsent}
                    onChange={(event) => setSensitiveUrlConsent(event.target.checked)}
                  />
                  <span>I understand the risk and consent to sharing the complete URL with external security providers.</span>
                </label>
              </div>
            )}

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
                  <small>Adds existing VirusTotal history and safely inspects redirect headers. It does not submit a new URL without your consent.</small>
                  <span className="mode-features"><b>Everything in Quick</b><b>Redirect path</b><b>VirusTotal history</b></span>
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
                <p className="section-kicker">{t(result.scanMode === "deep" ? "Deep intelligence report" : "Rapid risk report")}</p>
                <h2 id="result-title">{t(resultHeadline)}</h2>
              </div>
              <div className="result-actions">
                <div className="view-switch" aria-label={t("Result detail level")}>
                  <button type="button" className={view === "simple" ? "active" : ""} onClick={() => setView("simple")} aria-pressed={view === "simple"}>{t("Overview")}</button>
                  <button type="button" className={view === "analyst" ? "active" : ""} onClick={() => setView("analyst")} aria-pressed={view === "analyst"}>{t("Technical")}</button>
                </div>
                <button className="copy-button" type="button" onClick={() => void copyReport()}>{t(copyLabel)}</button>
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
                <div className="verdict-command"><span>{t("Recommended now")}</span><strong>{t(result.actions[0])}</strong></div>
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
                    <div className="card-title"><span aria-hidden="true">!</span><div><p>{t("Why it was flagged")}</p><h3>{t("Key findings")}</h3></div><b className="card-stat">{t(`${result.reasons.length} evidence signals`)}</b></div>
                    <ol className="finding-list">
                      {result.reasons.map((reason, index) => <li key={`${reason}-${index}`}><span>{String(index + 1).padStart(2, "0")}</span><p>{t(reason)}</p></li>)}
                    </ol>
                  </article>
                  <article className="result-list-card action-card">
                    <div className="card-title"><span aria-hidden="true">→</span><div><p>{t("Recommended response")}</p><h3>{t("What to do next")}</h3></div><b className="card-stat">{t(`${result.actions.length} safety steps`)}</b></div>
                    <ol className="action-list">
                      {result.actions.map((action, index) => <li key={action}><span>{index + 1}</span><p>{t(action)}</p></li>)}
                    </ol>
                  </article>
                </div>

                <div className="inspection-grid">
                  <article className="inspection-card signals-inspection">
                    <div className="inspection-head"><div><p>{t("Message analysis")}</p><h3>{t("Signals inspected")}</h3><small>{t("Local rule analysis")}</small></div><span>{t(`${detectedSignals} detected`)}</span></div>
                    <div className="signal-list signal-groups">
                      {signalGroups.map((group) => (
                        <section key={group.state} className={`signal-group signal-group-${group.state}`} aria-label={t(group.label)}>
                          <div className="signal-group-head"><span>{t(group.label)}</span><b>{group.signals.length}</b></div>
                          <div className="signal-group-grid">
                            {group.signals.map((signal) => (
                              <div key={signal.name} className={`signal-row signal-${signal.state}`}>
                                <span className="signal-state" aria-hidden="true">{signal.state === "clear" ? "✓" : "!"}</span>
                                <div><strong>{t(signal.name)}</strong><p>{t(signal.detail)}</p></div>
                                <b>{signal.count || t("Clear")}</b>
                              </div>
                            ))}
                          </div>
                        </section>
                      ))}
                    </div>
                  </article>

                  <article className="inspection-card providers-inspection">
                    <div className="inspection-head"><div><p>Threat intelligence</p><h3>Provider checks</h3><small>{t("Reputation and infrastructure")}</small></div><span>{t(`${result.analysis.providerCoverage.completed} completed`)}</span></div>
                    <div className="compact-providers">
                      {result.providers.map((provider, index) => (
                        <div key={`${provider.name}-${provider.subject}-${index}`} className={`compact-provider provider-${provider.state}`}>
                          <span className="provider-icon" aria-hidden="true">{providerIcon(provider.state)}</span>
                          <div><strong>{t(provider.name)}</strong><small>{provider.subject}</small><p>{t(provider.detail)}</p></div>
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
                      <div className="domain-intel-heading">
                        <div><span>{t("Domain Intelligence")}</span><strong>{t("Infrastructure and impersonation checks")}</strong></div>
                        <small>{t("Evidence is combined; no single signal proves safety.")}</small>
                      </div>
                      <div className="domain-intel-grid">
                        <article className={`domain-intel-card intel-${link.domainIntelligence.brand.state}`}>
                          <div className="domain-intel-top"><span>{t("Brand similarity")}</span><b>{link.domainIntelligence.brand.isTyposquat ? `${link.domainIntelligence.brand.similarity}%` : t("Clear")}</b></div>
                          <strong>{link.domainIntelligence.brand.suspectedBrand ?? t("No close brand match")}</strong>
                          <p>{link.domainIntelligence.brand.isTyposquat && link.domainIntelligence.brand.officialDomain
                            ? `${t("Official domain")}: ${link.domainIntelligence.brand.officialDomain}`
                            : t("No monitored brand look-alike was detected.")}</p>
                        </article>
                        <article className={`domain-intel-card intel-${link.domainIntelligence.dns.state}`}>
                          <div className="domain-intel-top"><span>{t("DNS footprint")}</span><b>{link.domainIntelligence.dns.state === "clear" ? t("Resolved") : t(link.domainIntelligence.dns.state)}</b></div>
                          <strong>{link.domainIntelligence.dns.addresses.length + link.domainIntelligence.dns.ipv6.length} {t("address records")}</strong>
                          <p>{link.domainIntelligence.dns.nameservers.length} {t("name servers")} · DNSSEC {link.domainIntelligence.dns.dnssecAuthenticated === true ? t("observed") : link.domainIntelligence.dns.dnssecAuthenticated === false ? t("not observed") : t("unknown")}</p>
                        </article>
                        <article className={`domain-intel-card intel-${link.domainIntelligence.certificate.state}`}>
                          <div className="domain-intel-top"><span>{t("Certificate records")}</span><b>CT</b></div>
                          <strong>{link.domainIntelligence.certificate.activeRecordCount} {t("active records")}</strong>
                          <p>{link.domainIntelligence.certificate.issuer
                            ? `${t("Issuer")}: ${link.domainIntelligence.certificate.issuer}`
                            : t("No active public record observed.")}</p>
                        </article>
                        <article className={`domain-intel-card intel-${link.domainIntelligence.redirects.state}`}>
                          <div className="domain-intel-top"><span>{t("Redirect path")}</span><b>{link.domainIntelligence.redirects.checked ? link.domainIntelligence.redirects.count : t("Deep only")}</b></div>
                          <strong>{link.domainIntelligence.redirects.checked
                            ? link.domainIntelligence.redirects.count === 0 ? t("Direct destination") : `${link.domainIntelligence.redirects.count} ${t("redirects")}`
                            : t("Not inspected")}</strong>
                          <p>{link.domainIntelligence.redirects.checked
                            ? `${t("Final domain")}: ${new URL(link.domainIntelligence.redirects.finalUrl).hostname}`
                            : t("Deep Scan checks headers without rendering the page.")}</p>
                        </article>
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
                <div className="analyst-tabs" role="tablist" aria-label={t("Technical result sections")}>
                  {analystTabs.map((tab) => (
                    <button key={tab} type="button" role="tab" aria-selected={activeTab === tab} className={activeTab === tab ? "active" : ""} onClick={() => setActiveTab(tab)}>{t(tab)}</button>
                  ))}
                </div>

                {activeTab === "Evidence" && (
                  <div className="tab-content evidence-table" role="tabpanel">
                    <div className="technical-summary"><span>{t("Local analysis")} <b>{formatDuration(result.analysis.timing.localAnalysisMs)}</b></span><span>{t("Live checks")} <b>{formatDuration(result.analysis.timing.liveChecksMs)}</b></span><span>{t("Rules")} <b>{result.analysis.rulesEvaluated}</b></span><span>{t("Lines")} <b>{result.analysis.messageStats.lines}</b></span></div>
                    {result.evidence.map((item, index) => (
                      <article key={`${item.source}-${index}`}><span className={`impact impact-${item.impact.toLowerCase()}`}>{t(item.impact)}</span><div><strong>{t(item.source)}</strong><p>{t(item.detail)}</p></div></article>
                    ))}
                  </div>
                )}

                {activeTab === "URLs" && (
                  <div className="tab-content url-grid" role="tabpanel">
                    {result.links.length ? result.links.map((link) => (
                      <article key={link.url} className="url-card">
                        <div className="url-card-head"><div><span>{t("Domain")}</span><strong>{link.domain}</strong></div><b>{t(`${link.riskScore}% link risk`)}</b></div>
                        <code>{link.url}</code>
                        <div className="technical-chips"><span>{link.technical.protocol}</span><span>.{link.technical.tld}</span><span>{link.technical.hostnameLength} {t("hostname characters")}</span><span>{t(link.technical.isShortener ? "Shortened URL" : "Direct URL")}</span><span>{t(link.technical.hasUserInfo ? "User-info present" : "No user-info")}</span><span>{t("Brand")}: {link.domainIntelligence.brand.isTyposquat ? link.domainIntelligence.brand.suspectedBrand : t("clear")}</span><span>DNS: {t(link.domainIntelligence.dns.state)}</span><span>CT: {link.domainIntelligence.certificate.activeRecordCount}</span><span>{t("Redirects")}: {link.domainIntelligence.redirects.checked ? link.domainIntelligence.redirects.count : t("Deep only")}</span></div>
                        <ul>{link.reasons.map((reason) => <li key={reason}>{t(reason)}</li>)}</ul>
                      </article>
                    )) : <p className="empty-state">{t("No URL was found in this message.")}</p>}
                  </div>
                )}

                {activeTab === "Providers" && (
                  <div className="tab-content provider-grid" role="tabpanel">
                    {result.providers.map((provider, index) => (
                      <article key={`${provider.name}-${provider.subject}-${index}`} className={`provider-card provider-${provider.state}`}>
                        <span className="provider-icon" aria-hidden="true">{providerIcon(provider.state)}</span>
                        <div><span>{provider.subject}</span><h3>{t(provider.name)}</h3><p>{t(provider.detail)}</p></div>
                        <b>{t(provider.label)}</b>
                      </article>
                    ))}
                  </div>
                )}

                {activeTab === "IOCs" && (
                  <div className="tab-content ioc-grid" role="tabpanel">
                    {(Object.entries(result.iocs) as Array<[keyof ScanResult["iocs"], string[]]>).map(([label, values]) => (
                      <article key={label}><h3>{t(iocLabels[label])}</h3>{values.length ? values.map((value) => <code key={value}>{value}</code>) : <p>{t("None found")}</p>}</article>
                    ))}
                  </div>
                )}
              </div>
            )}

            <DeepScanPanel
              result={result}
              selectedDeepUrl={selectedDeepUrl}
              setSelectedDeepUrl={setSelectedDeepUrl}
              consent={consent}
              setConsent={setConsent}
              deepSubmitting={deepSubmitting}
              deepJob={deepJob}
              submitFreshAnalysis={submitFreshAnalysis}
              deepTracking={deepTracking}
              deepElapsedSeconds={deepElapsedSeconds}
              refreshDeepAnalysis={refreshDeepAnalysis}
              sensitiveUrlConsent={sensitiveUrlConsent}
              setSensitiveUrlConsent={setSensitiveUrlConsent}
            />
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
