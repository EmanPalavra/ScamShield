import type { Metadata } from "next";
import { InfoShell } from "../info-shell";

export const metadata: Metadata = { title: "Privacy" };

const sections = [
  { id: "submitted-data", label: "Submitted data" },
  { id: "retention", label: "Retention boundary" },
  { id: "diagnostics", label: "Anonymous diagnostics" },
  { id: "providers", label: "External providers" },
  { id: "fresh-analysis", label: "Fresh analysis consent" },
];

export default function PrivacyPage() {
  return (
    <InfoShell
      page="privacy"
      eyebrow="Data handling"
      title="Privacy boundaries you can understand"
      intro="ScamShield minimizes retained application data and clearly separates local message analysis from external URL reputation checks. You should still remove private data before scanning."
      sections={sections}
    >
      <section id="submitted-data">
        <div className="info-number"><span>01</span><small>Input</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">What enters the scan</span>
          <h2>Only submit what is necessary to assess the risk</h2>
          <p>The service receives the message or URL you paste, basic request metadata required for security and rate limiting, and a Turnstile verification token when bot protection is configured.</p>
          <ul className="info-points">
            <li>Remove passwords, one-time codes, recovery links, identity numbers, and private internal URLs.</li>
            <li>Include enough surrounding wording to preserve context, but redact unrelated personal details.</li>
            <li>No ScamShield account is required to run a scan.</li>
          </ul>
        </div>
      </section>

      <section id="retention">
        <div className="info-number"><span>02</span><small>Storage</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Application boundary</span>
          <h2>Pasted messages are not intentionally saved to an app database</h2>
          <p>The current application does not maintain user profiles, scan history, or a database of submitted message bodies. A result is returned to the current browser session.</p>
          <ul className="info-points">
            <li>Abuse controls transform client IPs into server-secret HMAC buckets that rotate daily; raw IPs and enumerable unsalted hashes are not used as bucket identifiers.</li>
            <li>Cloudflare platform logs and security telemetry may exist according to the hosting account configuration.</li>
            <li>External providers maintain their own logs and retention rules independently of ScamShield.</li>
          </ul>
        </div>
      </section>

      <section id="diagnostics">
        <div className="info-number"><span>03</span><small>Optional</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Anonymous diagnostics</span>
          <h2>Quality metrics are sent only after you opt in</h2>
          <p>Anonymous diagnostics are disabled by default. If enabled in Settings, ScamShield records only the event type, scan mode, duration, broad result level, detected language, provider counts, and an optional structured result rating.</p>
          <ul className="info-points">
            <li>Messages, URLs, domains, IP addresses, account identifiers, and free-text comments are never written to the diagnostics dataset.</li>
            <li>Cloudflare Analytics Engine retains these aggregate data points for three months.</li>
            <li>User ratings are review signals only; they never become automatic training labels.</li>
            <li>Turning diagnostics off prevents all future diagnostic and feedback submissions from the browser.</li>
          </ul>
        </div>
      </section>

      <section id="providers">
        <div className="info-number"><span>04</span><small>Sharing</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">URL enrichment</span>
          <h2>External services receive only the data needed for their check</h2>
          <p>When configured, eligible public URL or domain information is sent to security and registration providers. Private and reserved network addresses and embedded credentials are blocked. Sensitive query values are removed by default, while sharing a complete tokenized URL requires a separate explicit opt-in. Provider privacy policies, logging practices, and terms still apply to accepted requests.</p>
          <div className="privacy-provider-grid">
            <div><strong>Google Safe Browsing</strong><p>Receives URLs for known-threat matching.</p></div>
            <div><strong>RDAP services</strong><p>Receive domain-registration queries, not the full message.</p></div>
            <div><strong>VirusTotal</strong><p>Receives URL-related requests during Deep Scan or a consented fresh analysis.</p></div>
          </div>
        </div>
      </section>

      <section id="fresh-analysis">
        <div className="info-number"><span>05</span><small>Consent</small></div>
        <div className="info-section-copy">
          <span className="info-section-label">Explicit external submission</span>
          <h2>A new VirusTotal analysis never starts automatically</h2>
          <p>Deep Scan first asks for an existing report. If you choose a fresh analysis, ScamShield displays a privacy warning and requires explicit consent before sending the URL. A tokenized URL also requires the separate exact-sharing consent.</p>
          <ul className="info-points">
            <li>Submitted URLs and results may become visible to VirusTotal and its security community.</li>
            <li>Never submit private, one-time, credential-bearing, intranet, or password-reset links.</li>
            <li>You can use the ScamShield result without starting a fresh VirusTotal analysis.</li>
          </ul>
          <div className="info-inline-note"><span aria-hidden="true">!</span><p><strong>Simple rule:</strong> if a link should not become public, do not submit it for fresh external analysis.</p></div>
        </div>
      </section>
    </InfoShell>
  );
}
