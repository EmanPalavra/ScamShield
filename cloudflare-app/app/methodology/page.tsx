import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "Methodology" };

const sections = [
  { id: "rule-model", label: "Rule model" },
  { id: "signal-interaction", label: "Signal interaction" },
  { id: "provider-evidence", label: "Provider evidence" },
  { id: "risk-bands", label: "Risk bands" },
];

export default function MethodologyPage() {
  return (
    <InfoShell
      page="methodology"
      eyebrow="Detection methodology"
      title="A score built from visible evidence"
      intro="ScamShield is an explainable triage system. It combines weighted language rules, passive URL forensics, and time-bounded reputation checks; the result is not an opaque AI probability."
      sections={sections}
    >
      <section id="rule-model">
        <div className="info-number"><span>01</span><small>Rules</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Deterministic analysis</span>
          <h2>Each warning has a traceable reason</h2>
          <p>The message is normalized and evaluated against weighted patterns for phishing, fake charges, delivery fraud, crypto and investment schemes, advance-fee offers, job scams, marketplace payments, document phishing, and impersonation.</p>
          <ul className="info-points">
            <li>Category rules identify the likely scam scenario.</li>
            <li>Signal rules measure urgency, credentials, payments, consequences, rewards, calls to action, and brand imitation.</li>
            <li>Formatting is supporting evidence; capital letters alone cannot create a high-risk verdict.</li>
          </ul>
        </div>
      </section>

      <section id="signal-interaction">
        <div className="info-number"><span>02</span><small>Context</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Combined behavior</span>
          <h2>Dangerous combinations matter more than isolated words</h2>
          <p>A single word such as “today” or “payment” is weak evidence. The score rises when a recognizable scam category appears together with a deadline, threatened loss, sensitive-data request, payment instruction, or linked action.</p>
          <ul className="info-points">
            <li>Multiple independent signals can raise a message into a stronger risk band.</li>
            <li>The final result preserves the stronger of message risk, link risk, and their combined estimate.</li>
            <li>Confirmed provider threats override weaker local uncertainty and raise the result to High.</li>
          </ul>
        </div>
      </section>

      <section id="provider-evidence">
        <div className="info-number"><span>03</span><small>Sources</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Live reputation</span>
          <h2>External checks add evidence, not silent assumptions</h2>
          <p>Google Safe Browsing and RDAP run concurrently with VirusTotal history during Deep Scan. Provider calls have a bounded wait time and short-lived cache so a slow third party does not indefinitely block the report.</p>
          <ul className="info-points">
            <li>Clear means the queried source returned no listed threat for that check.</li>
            <li>Unavailable means a key, quota, network response, or provider result was missing.</li>
            <li>No report is different from safe: a new or targeted campaign may have no reputation history yet.</li>
          </ul>
        </div>
      </section>

      <section id="risk-bands">
        <div className="info-number"><span>04</span><small>Output</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Conservative interpretation</span>
          <h2>Three bands communicate urgency without false certainty</h2>
          <div className="risk-band-grid" aria-label="Risk score bands">
            <div className="band-low"><strong>Low</strong><span>0 to 33</span><p>No strong signal confirmed. Continue with normal caution.</p></div>
            <div className="band-medium"><strong>Medium</strong><span>34 to 66</span><p>Independent verification is needed before interaction.</p></div>
            <div className="band-high"><strong>High</strong><span>67 to 99</span><p>Do not click, reply, pay, or share sensitive information.</p></div>
          </div>
        </div>
      </section>

      <aside className="method-note"><span aria-hidden="true">!</span><div><strong>Validation status</strong><p>Regression examples confirm expected behavior across known scenarios, but they do not establish real-world accuracy. Publishing precision, recall, or F1 would require a larger, representative, locked holdout dataset.</p></div></aside>
    </InfoShell>
  );
}
