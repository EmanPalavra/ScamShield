import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "Methodology" };

export default function MethodologyPage() {
  return (
    <InfoShell
      eyebrow="Detection methodology"
      title="Signals, providers, and conservative decisions"
      intro="The score is an explainable triage estimate. It is not a machine-learning probability and it is not a substitute for an antivirus product or professional incident response."
    >
      <section><span className="info-number">01</span><div><h2>Message score</h2><p>Weighted rules identify scam categories and pressure tactics. Credential requests and irreversible payment methods carry more weight than generic urgency or unusual formatting.</p></div></section>
      <section><span className="info-number">02</span><div><h2>Link score</h2><p>Structural URL signals are combined with domain age. A confirmed live-provider threat match raises the final result to high risk because current blocklist evidence is stronger than wording alone.</p></div></section>
      <section><span className="info-number">03</span><div><h2>Provider execution</h2><p>Google Safe Browsing, RDAP, and VirusTotal checks run concurrently and are time-bounded. Short-lived response caching reduces provider quota use without treating old data as current forever.</p></div></section>
      <section><span className="info-number">04</span><div><h2>Risk bands</h2><p>Scores from 0–33 are Low, 34–66 Medium, and 67–99 High. The interface deliberately avoids “safe” or “100% malicious” claims because reputation gaps and targeted attacks create uncertainty.</p></div></section>
      <aside className="method-note"><strong>Validation status</strong><p>The earlier 35-sample development set is useful for regression testing, but it is too small to establish real-world accuracy. A larger locked holdout set is required before publishing precision, recall, or F1 claims.</p></aside>
    </InfoShell>
  );
}
