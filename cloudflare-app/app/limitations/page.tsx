import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "Limitations" };

const sections = [
  { id: "unknown-attacks", label: "Unknown attacks" },
  { id: "missing-context", label: "Missing context" },
  { id: "classification-errors", label: "Classification errors" },
  { id: "provider-dependencies", label: "Provider dependencies" },
];

export default function LimitationsPage() {
  return (
    <InfoShell
      page="limitations"
      eyebrow="Know the boundaries"
      title="What a scan can—and cannot—prove"
      intro="ScamShield helps prioritize risk. It cannot authenticate a sender, guarantee a link is safe, replace endpoint protection, or investigate evidence that was not included in the submitted text."
      sections={sections}
    >
      <section id="unknown-attacks">
        <div className="info-number"><span>01</span><small>Fresh threats</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Reputation delay</span>
          <h2>A brand-new attack may have no history yet</h2>
          <p>Blocklists and reputation databases improve after threats are discovered. A newly registered phishing page, private campaign, or one-time domain may return no provider warning during its earliest hours.</p>
          <ul className="info-points">
            <li>“No report” means no usable provider record was found—not that the destination is trusted.</li>
            <li>A clean provider result covers only that provider and that moment in time.</li>
            <li>Targeted scams may never become common enough to appear on public reputation lists.</li>
          </ul>
        </div>
      </section>

      <section id="missing-context">
        <div className="info-number"><span>02</span><small>Visibility</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">What the scanner cannot see</span>
          <h2>The result is limited to the text and URLs you provide</h2>
          <p>ScamShield cannot independently verify the sender, reconstruct an entire conversation, inspect mail routing, open attachments, decode a QR image, or observe what happens after a login.</p>
          <ul className="info-points">
            <li>Missing previous messages can change the meaning of an otherwise harmless sentence.</li>
            <li>Screenshots, PDFs, files, and QR codes must be assessed separately.</li>
            <li>A legitimate-looking sender name can be spoofed; verify through an independently found channel.</li>
          </ul>
        </div>
      </section>

      <section id="classification-errors">
        <div className="info-number"><span>03</span><small>Uncertainty</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">False positives and false negatives</span>
          <h2>Rules can overreact—or miss unfamiliar wording</h2>
          <p>Legitimate billing, recruiting, or support messages sometimes use urgent language. Skilled attackers can also avoid familiar phrases, use images instead of text, or build trust gradually before asking for money.</p>
          <ul className="info-points">
            <li>High means strong warning evidence was found; it is not a legal determination of fraud.</li>
            <li>Low means strong evidence was not found; it is not an assurance of safety.</li>
            <li>Medium is a deliberate pause signal: verify before clicking, replying, paying, or sharing data.</li>
          </ul>
        </div>
      </section>

      <section id="provider-dependencies">
        <div className="info-number"><span>04</span><small>Availability</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">External service limits</span>
          <h2>Provider coverage can be incomplete or temporarily unavailable</h2>
          <p>Google Safe Browsing, RDAP, and VirusTotal can time out, enforce quotas, return partial data, or change availability. ScamShield surfaces that state instead of treating a missing check as clean.</p>
          <ul className="info-points">
            <li>Fresh VirusTotal timing is controlled by its external queue and participating engines.</li>
            <li>Domain registration dates may be hidden, inconsistent, or unavailable through RDAP.</li>
            <li>Network and provider failures reduce coverage but do not erase the local message analysis.</li>
          </ul>
        </div>
      </section>

      <aside className="method-note danger-note"><span aria-hidden="true">!</span><div><strong>When the stakes are high</strong><p>If the request involves money, account access, identity documents, workplace systems, threats, or personal safety, stop and verify through an official channel or a qualified professional—even if the scan result is Low.</p></div></aside>
    </InfoShell>
  );
}
