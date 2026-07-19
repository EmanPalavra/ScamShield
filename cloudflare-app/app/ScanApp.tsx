"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

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
  deepScan: {
    checkedExistingReport: boolean;
    canSubmitFreshAnalysis: boolean;
    urls: string[];
    privacyNotice: string;
  };
  limits: { maxUrls: number; truncatedUrls: boolean };
}

interface RuntimeConfig {
  turnstileSiteKey: string | null;
  turnstileConfigured: boolean;
  providers: {
    googleSafeBrowsing: boolean;
    virusTotal: boolean;
    rdap: boolean;
  };
}

interface DeepJob {
  analysisId: string;
  url: string;
  status: string;
  completed: boolean;
  stats: Record<string, number> | null;
  verdict: string | null;
  riskState: string;
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
          "expired-callback": () => void;
          "error-callback": () => void;
        },
      ) => string;
      reset: (widgetId?: string) => void;
      remove: (widgetId: string) => void;
    };
  }
}

const EXAMPLE_MESSAGE =
  "URGENT: Your bank account will be locked within 30 minutes. Verify your login now at https://secure-account-check.xyz/login and enter your one-time code.";

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

function SiteHeader() {
  const [theme, setTheme] = useState<"light" | "dark">("light");

  useEffect(() => {
    const savedTheme = window.localStorage.getItem("scamshield-theme");
    const nextTheme = savedTheme === "dark" || savedTheme === "light"
      ? savedTheme
      : window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    setTheme(nextTheme);
    document.documentElement.dataset.theme = nextTheme;
  }, []);

  function toggleTheme() {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    document.documentElement.dataset.theme = nextTheme;
    window.localStorage.setItem("scamshield-theme", nextTheme);
  }

  return (
    <header className="site-header">
      <Link className="brand" href="/" aria-label="ScamShield home">
        <span className="brand-mark" aria-hidden="true">S</span>
        <span>SCAMSHIELD</span>
      </Link>
      <nav aria-label="Main navigation">
        <Link href="/how-it-works">How it works</Link>
        <Link href="/methodology">Methodology</Link>
        <Link href="/privacy">Privacy</Link>
        <Link href="/limitations">Limitations</Link>
        <button
          className="theme-toggle"
          type="button"
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        >
          <span aria-hidden="true">{theme === "dark" ? "☀" : "◐"}</span>
          <span>{theme === "dark" ? "Light" : "Dark"}</span>
        </button>
      </nav>
    </header>
  );
}

function SiteFooter() {
  return (
    <footer className="site-footer">
      <div>
        <span className="footer-brand">SCAMSHIELD</span>
        <p>Explainable scam triage for suspicious messages and links.</p>
      </div>
      <p>
        A risk estimate is not a guarantee. For money, credentials, or identity documents, verify through an official channel you find independently.
      </p>
    </footer>
  );
}

export function ScanApp() {
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
  const turnstileContainer = useRef<HTMLDivElement>(null);
  const turnstileWidgetId = useRef<string | null>(null);
  const resultsRef = useRef<HTMLElement>(null);

  useEffect(() => {
    fetch("/api/config")
      .then((response) => response.json() as Promise<RuntimeConfig>)
      .then(setConfig)
      .catch(() => setConfig(null));
  }, []);

  useEffect(() => {
    if (!config?.turnstileConfigured || !config.turnstileSiteKey || !turnstileContainer.current) return;

    const renderWidget = () => {
      if (!window.turnstile || !turnstileContainer.current || turnstileWidgetId.current) return;
      turnstileWidgetId.current = window.turnstile.render(turnstileContainer.current, {
        sitekey: config.turnstileSiteKey ?? "",
        theme: "auto",
        size: "flexible",
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
    setMessage("");
    setResult(null);
    setError("");
    setConsent(false);
    setSelectedDeepUrl("");
    setDeepJob(null);
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

  async function pollDeepAnalysis(analysisId: string, url: string) {
    for (let attempt = 0; attempt < 24; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, attempt === 0 ? 2_000 : 3_000));
      try {
        const response = await fetch(`/api/deep/status?id=${encodeURIComponent(analysisId)}`);
        const payload = (await response.json()) as Partial<DeepJob> & { error?: string };
        if (!response.ok) {
          if (response.status === 429) continue;
          throw new Error(payload.error ?? "Analysis status could not be retrieved.");
        }
        const nextJob: DeepJob = {
          analysisId,
          url,
          status: payload.status ?? "queued",
          completed: payload.completed === true,
          stats: payload.stats ?? null,
          verdict: payload.verdict ?? null,
          riskState: payload.riskState ?? "pending",
        };
        setDeepJob(nextJob);
        if (nextJob.completed) return;
      } catch (pollError) {
        setDeepJob((current) => ({
          analysisId,
          url,
          status: current?.status ?? "queued",
          completed: false,
          stats: current?.stats ?? null,
          verdict: current?.verdict ?? null,
          riskState: current?.riskState ?? "pending",
          error: pollError instanceof Error ? pollError.message : "Analysis tracking failed.",
        }));
        return;
      }
    }
    setDeepJob((current) =>
      current
        ? { ...current, error: "The analysis is still running. You can retry Deep Scan later to read the latest report." }
        : null,
    );
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
      const payload = (await response.json()) as { analysisId?: string; url?: string; status?: string; error?: string };
      if (!response.ok || !payload.analysisId) throw new Error(payload.error ?? "Fresh analysis could not be started.");
      const job: DeepJob = {
        analysisId: payload.analysisId,
        url: payload.url ?? selectedDeepUrl,
        status: payload.status ?? "queued",
        completed: false,
        stats: null,
        verdict: null,
        riskState: "pending",
      };
      setDeepJob(job);
      resetTurnstile();
      await pollDeepAnalysis(job.analysisId, job.url);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Fresh analysis could not be started.");
    } finally {
      setDeepSubmitting(false);
    }
  }

  return (
    <>
      <SiteHeader />
      <main>
        <section className="hero" aria-labelledby="hero-title">
          <div className="hero-copy">
            <p className="eyebrow">Message & URL risk analysis</p>
            <h1 id="hero-title">Pause before you trust the message.</h1>
            <p className="hero-lead">
              ScamShield explains suspicious wording, inspects links, and checks live reputation sources without visiting the destination.
            </p>
            <div className="trust-row" aria-label="Service qualities">
              <span><b aria-hidden="true">✓</b> Explainable results</span>
              <span><b aria-hidden="true">✓</b> No account required</span>
              <span><b aria-hidden="true">✓</b> Consent before fresh analysis</span>
            </div>
          </div>
          <aside className="safety-note">
            <span className="note-icon" aria-hidden="true">i</span>
            <div>
              <strong>Safe by design</strong>
              <p>ScamShield never opens the suspicious page. It analyzes the text, URL structure, and provider reports.</p>
            </div>
          </aside>
        </section>

        <section className="scanner-shell" aria-labelledby="scanner-title">
          <div className="scanner-heading">
            <div>
              <p className="section-kicker">Start a check</p>
              <h2 id="scanner-title">Paste the full message or link</h2>
            </div>
            <div className="view-switch" aria-label="Result detail level">
              <button type="button" className={view === "simple" ? "active" : ""} onClick={() => setView("simple")} aria-pressed={view === "simple"}>Simple view</button>
              <button type="button" className={view === "analyst" ? "active" : ""} onClick={() => setView("analyst")} aria-pressed={view === "analyst"}>Analyst view</button>
            </div>
          </div>

          <form onSubmit={onSubmit}>
            <label htmlFor="message">Message or URL</label>
            <textarea
              id="message"
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              maxLength={10_000}
              placeholder="Paste an SMS, email, chat message, or suspicious URL…"
              rows={8}
              disabled={Boolean(loadingMode)}
            />
            <div className="field-footer">
              <span>Do not include passwords, one-time codes, or private internal links.</span>
              <span>{message.length.toLocaleString()} / 10,000</span>
            </div>

            {config?.turnstileConfigured ? (
              <div className="turnstile-wrap" aria-label="Human verification">
                <div ref={turnstileContainer} />
              </div>
            ) : (
              <div className="protection-status">
                <span aria-hidden="true">i</span>
                <p><strong>Preview protection:</strong> request limits are active. Cloudflare Turnstile will appear here when production keys are connected.</p>
              </div>
            )}

            {error && <div className="error-banner" role="alert">{error}</div>}

            <div className="form-actions">
              <button className="button primary" type="submit" disabled={Boolean(loadingMode)}>
                <span>Quick Scan</span>
                <small>Message + domain reputation</small>
              </button>
              <button className="button secondary" type="button" onClick={() => void runScan("deep")} disabled={Boolean(loadingMode)}>
                <span>Deep Scan</span>
                <small>Includes existing VirusTotal report</small>
              </button>
            </div>
            <div className="utility-actions">
              <button type="button" className="text-button" onClick={clearAll}>Clear</button>
              <button type="button" className="text-button" onClick={() => { setMessage(EXAMPLE_MESSAGE); setError(""); }}>Try an example</button>
            </div>
          </form>

          {loadingMode && (
            <div className="progress-panel" role="status" aria-live="polite">
              <div className="progress-heading">
                <span className="spinner" aria-hidden="true" />
                <div><strong>{loadingMode === "deep" ? "Deep Scan in progress" : "Quick Scan in progress"}</strong><p>Live provider checks can take a few seconds.</p></div>
              </div>
              <ol>
                {progressLabels.map((label, index) => (
                  <li key={label} className={index < progressStep ? "done" : index === progressStep ? "active" : ""}>
                    <span aria-hidden="true">{index < progressStep ? "✓" : index + 1}</span>{label}
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
                <p className="section-kicker">{result.scanMode === "deep" ? "Deep Scan result" : "Quick Scan result"}</p>
                <h2 id="result-title">What this result means</h2>
              </div>
              <button className="copy-button" type="button" onClick={() => void copyReport()}>{copyLabel}</button>
            </div>

            <div className="result-summary">
              <div className="risk-visual" aria-label={`${result.riskLevel} risk, ${result.riskPercent} percent`}>
                <span className="risk-symbol" aria-hidden="true">{riskIcon(result.riskLevel)}</span>
                <strong>{result.riskPercent}%</strong>
                <span>{result.riskLevel} risk</span>
              </div>
              <div className="risk-copy">
                <span className="risk-pill">{result.riskLabel}</span>
                <h3>{result.scamType}</h3>
                <p>
                  {result.riskLevel === "High"
                    ? "Strong warning signals were found. Treat the message or link as unsafe until independently verified."
                    : result.riskLevel === "Medium"
                      ? "Some warning signals need independent verification before you interact."
                      : "No strong threat signal was found, but new or targeted scams may not yet appear in reputation sources."}
                </p>
                <div className="scan-meta">
                  <span>{new Date(result.scannedAt).toLocaleString()}</span>
                  <span>{result.links.length} URL{result.links.length === 1 ? "" : "s"} checked</span>
                </div>
              </div>
            </div>

            {view === "simple" ? (
              <div className="simple-grid">
                <article className="result-list-card">
                  <div className="card-title"><span aria-hidden="true">?</span><h3>Three key reasons</h3></div>
                  <ol className="numbered-list">
                    {result.reasons.slice(0, 3).map((reason, index) => <li key={reason}><span>{index + 1}</span><p>{reason}</p></li>)}
                  </ol>
                </article>
                <article className="result-list-card action-card">
                  <div className="card-title"><span aria-hidden="true">→</span><h3>What to do next</h3></div>
                  <ol className="numbered-list">
                    {result.actions.slice(0, 3).map((action, index) => <li key={action}><span>{index + 1}</span><p>{action}</p></li>)}
                  </ol>
                </article>
              </div>
            ) : (
              <div className="analyst-panel">
                <div className="analyst-tabs" role="tablist" aria-label="Analyst result sections">
                  {analystTabs.map((tab) => (
                    <button key={tab} type="button" role="tab" aria-selected={activeTab === tab} className={activeTab === tab ? "active" : ""} onClick={() => setActiveTab(tab)}>{tab}</button>
                  ))}
                </div>

                {activeTab === "Evidence" && (
                  <div className="tab-content evidence-table" role="tabpanel">
                    {result.evidence.map((item, index) => (
                      <article key={`${item.source}-${index}`}>
                        <span className={`impact impact-${item.impact.toLowerCase()}`}>{item.impact}</span>
                        <div><strong>{item.source}</strong><p>{item.detail}</p></div>
                      </article>
                    ))}
                  </div>
                )}

                {activeTab === "URLs" && (
                  <div className="tab-content url-grid" role="tabpanel">
                    {result.links.length ? result.links.map((link) => (
                      <article key={link.url} className="url-card">
                        <div className="url-card-head"><div><span>Domain</span><strong>{link.domain}</strong></div><b>{link.riskScore}% link risk</b></div>
                        <code>{link.url}</code>
                        <ul>{link.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                      </article>
                    )) : <p className="empty-state">No URL was found in this message.</p>}
                  </div>
                )}

                {activeTab === "Providers" && (
                  <div className="tab-content provider-grid" role="tabpanel">
                    {result.providers.map((provider, index) => (
                      <article key={`${provider.name}-${provider.subject}-${index}`} className={`provider-card provider-${provider.state}`}>
                        <span className="provider-icon" aria-hidden="true">{providerIcon(provider.state)}</span>
                        <div><span>{provider.subject}</span><h3>{provider.name}</h3><p>{provider.detail}</p></div>
                        <b>{provider.label}</b>
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
                  <div className="deep-icon" aria-hidden="true">D</div>
                  <div>
                    <p className="section-kicker">Optional second stage</p>
                    <h3 id="fresh-analysis-title">Fresh VirusTotal analysis</h3>
                    <p>
                      {result.deepScan.checkedExistingReport
                        ? "ScamShield checked the latest existing report first. You can now choose whether to request a new analysis."
                        : "No URL was found, so VirusTotal cannot run a fresh analysis."}
                    </p>
                  </div>
                </div>

                {result.deepScan.canSubmitFreshAnalysis ? (
                  <div className="consent-box">
                    {result.deepScan.urls.length > 1 && (
                      <label className="select-label">URL to submit
                        <select value={selectedDeepUrl} onChange={(event) => setSelectedDeepUrl(event.target.value)}>
                          {result.deepScan.urls.map((url) => <option key={url} value={url}>{url}</option>)}
                        </select>
                      </label>
                    )}
                    <div className="privacy-warning"><span aria-hidden="true">!</span><p>{result.deepScan.privacyNotice}</p></div>
                    <label className="consent-check">
                      <input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} />
                      <span>I understand and explicitly consent to sending this URL to VirusTotal for a new public analysis.</span>
                    </label>
                    <button className="button deep-submit" type="button" disabled={!consent || deepSubmitting} onClick={() => void submitFreshAnalysis()}>
                      {deepSubmitting ? "Submitting and tracking…" : "Submit URL and track analysis"}
                    </button>
                  </div>
                ) : result.deepScan.urls.length > 0 ? (
                  <div className="provider-missing">Fresh analysis is ready in the code but needs a VirusTotal API key in the hosted environment.</div>
                ) : null}

                {deepJob && (
                  <div className={`deep-job job-${deepJob.riskState}`} role="status">
                    <span className={deepJob.completed ? "job-check" : "spinner"} aria-hidden="true">{deepJob.completed ? "✓" : ""}</span>
                    <div>
                      <strong>{deepJob.completed ? `Analysis complete: ${deepJob.verdict ?? "report ready"}` : `VirusTotal status: ${deepJob.status}`}</strong>
                      <p>{deepJob.completed && deepJob.stats ? `${deepJob.stats.malicious ?? 0} malicious, ${deepJob.stats.suspicious ?? 0} suspicious, ${deepJob.stats.harmless ?? 0} harmless verdicts.` : deepJob.error ?? "ScamShield is checking for a completed result every few seconds."}</p>
                    </div>
                  </div>
                )}
              </section>
            )}
          </section>
        )}

        <section className="method-strip" aria-label="Scan stages">
          <div><span>01</span><strong>Message signals</strong><p>Urgency, credentials, payment pressure, and scam language.</p></div>
          <div><span>02</span><strong>URL structure</strong><p>Domain shape, look-alikes, risky paths, and registration age.</p></div>
          <div><span>03</span><strong>Live reputation</strong><p>Google Safe Browsing, RDAP, and optional VirusTotal reports.</p></div>
          <div><span>04</span><strong>Clear action</strong><p>A practical summary for everyday users and technical evidence for analysts.</p></div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}

export { SiteFooter, SiteHeader };
