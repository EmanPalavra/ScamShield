import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "How it works" };

const sections = [
  { id: "message-analysis", label: "Message analysis" },
  { id: "url-inspection", label: "URL inspection" },
  { id: "reputation-checks", label: "Reputation checks" },
  { id: "explained-verdict", label: "Explained verdict" },
];

export default function HowItWorksPage() {
  return (
    <InfoShell
      page="how-it-works"
      eyebrow="Product guide"
      title="From suspicious message to clear next step"
      intro="ScamShield separates the message, the link, and live reputation evidence so you can see what was checked, what was found, and what still remains uncertain."
      sections={sections}
    >
      <section id="message-analysis">
        <div className="info-number"><span>01</span><small>Input</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Local language analysis</span>
          <h2>The complete message is read as one conversation</h2>
          <p>Whitespace and line breaks are normalized before more than one hundred explainable rules inspect the wording. This lets a long email, copied SMS thread, or multi-line job offer be understood as a single message instead of disconnected fragments.</p>
          <ul className="info-points">
            <li>Looks for urgency, threatened consequences, credential requests, payment pressure, rewards, impersonation, and forced calls to action.</li>
            <li>Recognizes common English and Bosnian/Croatian/Serbian wording, including several scam-category combinations.</li>
            <li>Counts message length, lines, formatting pressure, and the strength of interacting signals.</li>
          </ul>
        </div>
      </section>

      <section id="url-inspection">
        <div className="info-number"><span>02</span><small>Structure</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Passive URL forensics</span>
          <h2>The destination is parsed without opening the page</h2>
          <p>ScamShield extracts up to three URLs and inspects their structure. It does not render the destination, execute its scripts, submit forms, or sign in to the site.</p>
          <ul className="info-points">
            <li>Checks HTTPS use, raw IP addresses, Punycode, shorteners, embedded user information, path depth, and query parameters.</li>
            <li>Separates the real hostname from distracting text and reports the exact domain being evaluated.</li>
            <li>Uses RDAP registration data when available to identify very new domains.</li>
          </ul>
          <div className="info-inline-note"><span aria-hidden="true">✓</span><p><strong>Safer by design:</strong> the suspicious website is never visited by your browser through ScamShield.</p></div>
        </div>
      </section>

      <section id="reputation-checks">
        <div className="info-number"><span>03</span><small>Intel</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Independent providers</span>
          <h2>Reputation evidence is checked in parallel</h2>
          <p>Configured provider checks run concurrently under a short time limit. A missing or timed-out provider is shown as unavailable—it is never silently interpreted as a clean result.</p>
          <ul className="info-points">
            <li><strong>Quick Scan:</strong> message rules, URL structure, Google Safe Browsing, and RDAP domain age.</li>
            <li><strong>Deep Scan:</strong> everything in Quick Scan plus the latest existing VirusTotal URL report.</li>
            <li>A fresh VirusTotal submission is optional, clearly labeled, and requires explicit consent.</li>
          </ul>
        </div>
      </section>

      <section id="explained-verdict">
        <div className="info-number"><span>04</span><small>Decision</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Actionable result</span>
          <h2>Evidence becomes a decision you can verify</h2>
          <p>The strongest message and link evidence determines the risk band. A convincing scam message is not downgraded merely because its URL is technically ordinary or newly created.</p>
          <ul className="info-points">
            <li><strong>Overview</strong> explains the risk, key findings, inspected signals, provider coverage, and recommended actions.</li>
            <li><strong>Technical</strong> exposes evidence, URL facts, provider responses, and extracted indicators of compromise.</li>
            <li>Low, Medium, and High describe observed risk—not a promise that content is safe or malicious with certainty.</li>
          </ul>
        </div>
      </section>
    </InfoShell>
  );
}
