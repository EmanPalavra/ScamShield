import type { Dispatch, SetStateAction } from "react";
import type { DeepJob, ScanResult } from "./types";

interface DeepScanPanelProps {
  result: ScanResult;
  selectedDeepUrl: string;
  setSelectedDeepUrl: Dispatch<SetStateAction<string>>;
  consent: boolean;
  setConsent: Dispatch<SetStateAction<boolean>>;
  deepSubmitting: boolean;
  deepJob: DeepJob | null;
  submitFreshAnalysis(): Promise<void>;
  deepTracking: boolean;
  deepElapsedSeconds: number;
  refreshDeepAnalysis(): void;
  sensitiveUrlConsent: boolean;
  setSensitiveUrlConsent: Dispatch<SetStateAction<boolean>>;
}

export function DeepScanPanel({
  result,
  selectedDeepUrl,
  setSelectedDeepUrl,
  consent,
  setConsent,
  deepSubmitting,
  deepJob,
  submitFreshAnalysis,
  deepTracking,
  deepElapsedSeconds,
  refreshDeepAnalysis,
  sensitiveUrlConsent,
  setSensitiveUrlConsent,
}: DeepScanPanelProps) {
  if (result.scanMode !== "deep") return null;
  const selectedLink = result.links.find((link) => link.url === selectedDeepUrl);
  const selectedHasSensitiveUrl = Boolean(selectedLink?.externalSharing.sensitiveParameters.length);

  return (
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
                    {selectedHasSensitiveUrl && (
                      <label className="consent-check sensitive-consent-check">
                        <input
                          type="checkbox"
                          checked={sensitiveUrlConsent}
                          onChange={(event) => setSensitiveUrlConsent(event.target.checked)}
                        />
                        <span>I understand that this URL contains an access value and consent to sending the complete URL to VirusTotal.</span>
                      </label>
                    )}
                    <div className="privacy-warning"><span aria-hidden="true">!</span><p>{result.deepScan.privacyNotice}</p></div>
                    <label className="consent-check"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} /><span>I understand and explicitly consent to sending this URL to VirusTotal for a new public analysis.</span></label>
                    <button className="button deep-submit" type="button" disabled={!consent || (selectedHasSensitiveUrl && !sensitiveUrlConsent) || deepSubmitting || Boolean(deepJob && !deepJob.completed)} onClick={() => void submitFreshAnalysis()}>
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
  );
}
