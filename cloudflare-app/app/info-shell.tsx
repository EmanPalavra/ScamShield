import Link from "next/link";
import type { ReactNode } from "react";
import { LocalizedInfoContent } from "./localized-info-content";
import { SiteFooter, SiteHeader } from "./site-chrome";

export type InfoPageKey = "how-it-works" | "methodology" | "privacy" | "limitations";

interface InfoSectionLink {
  id: string;
  label: string;
}

const pageNavigation: Array<{ key: InfoPageKey; href: string; label: string; description: string; symbol: string }> = [
  { key: "how-it-works", href: "/how-it-works", label: "How it works", description: "From input to verdict", symbol: "01" },
  { key: "methodology", href: "/methodology", label: "Methodology", description: "Scoring and evidence", symbol: "02" },
  { key: "privacy", href: "/privacy", label: "Privacy", description: "How data is handled", symbol: "03" },
  { key: "limitations", href: "/limitations", label: "Limitations", description: "What results cannot prove", symbol: "04" },
];

const pageVisuals: Record<InfoPageKey, { code: string; label: string; title: string; detail: string; status: string }> = {
  "how-it-works": {
    code: "FLOW",
    label: "Decision pipeline",
    title: "Four layers. One clear answer.",
    detail: "Language, URL structure, live reputation, and an explainable recommendation.",
    status: "4 stages",
  },
  methodology: {
    code: "RULE",
    label: "Evidence model",
    title: "Signals are weighted, never hidden.",
    detail: "The score is built from observable evidence, not an unexplained AI confidence number.",
    status: "3 risk bands",
  },
  privacy: {
    code: "LOCK",
    label: "Data boundary",
    title: "Local first. External only when needed.",
    detail: "Message analysis stays inside the scan flow; URL reputation checks have visible provider boundaries.",
    status: "Consent gated",
  },
  limitations: {
    code: "EDGE",
    label: "Safety boundary",
    title: "A risk estimate is not a guarantee.",
    detail: "Unknown campaigns, missing context, and provider gaps still require independent verification.",
    status: "Human check",
  },
};

export function InfoShell({
  page,
  eyebrow,
  title,
  intro,
  sections,
  children,
}: {
  page: InfoPageKey;
  eyebrow: string;
  title: string;
  intro: string;
  sections: InfoSectionLink[];
  children: ReactNode;
}) {
  const visual = pageVisuals[page];
  const activePath = `/${page}`;

  return (
    <>
      <SiteHeader activePath={activePath} />
      <main className={`info-main info-${page}`}>
        <article className="info-page">
          <nav className="info-tabs" aria-label="ScamShield guides">
            {pageNavigation.map((item) => (
              <Link key={item.key} href={item.href} className={item.key === page ? "active" : ""} aria-current={item.key === page ? "page" : undefined} title={item.description}>
                <span>{item.symbol}</span>
                <strong>{item.label}</strong>
              </Link>
            ))}
          </nav>

          <div className="info-hero-grid">
            <header className="info-hero">
              <p className="eyebrow"><span aria-hidden="true" />{eyebrow}</p>
              <h1>{title}</h1>
              <p>{intro}</p>
              <div className="info-hero-pills" aria-label="Guide qualities">
                <span>Plain language</span>
                <span>Evidence first</span>
                <span>No hidden claims</span>
              </div>
            </header>

            <aside className="info-visual" aria-label={`${visual.label} summary`}>
              <div className="info-visual-top"><span>{visual.label}</span><b>{visual.status}</b></div>
              <div className="info-visual-stage" aria-hidden="true">
                <i className="info-orbit info-orbit-outer"><span /></i>
                <i className="info-orbit info-orbit-inner"><span /></i>
                <div className="info-visual-core">
                  <small>SCAMSHIELD</small>
                  <strong>{visual.code}</strong>
                  <em>ACTIVE</em>
                </div>
                <span className="info-scan-line" />
              </div>
              <strong>{visual.title}</strong>
              <p>{visual.detail}</p>
              <div className="info-visual-meter" aria-hidden="true"><span /><span /><span /><span /></div>
            </aside>
          </div>

          <div className="info-layout">
            <aside className="info-toc">
              <p>On this page</p>
              <nav aria-label="On this page">
                {sections.map((section, index) => <a key={section.id} href={`#${section.id}`}><span>{String(index + 1).padStart(2, "0")}</span>{section.label}</a>)}
              </nav>
              <div className="info-toc-note"><span aria-hidden="true">i</span><p>Use these pages to understand what the result means before acting on it.</p></div>
            </aside>
            <div className="info-content"><LocalizedInfoContent page={page} sectionIds={sections.map((section) => section.id)}>{children}</LocalizedInfoContent></div>
          </div>

          <div className="info-cta">
            <div><span>Ready to check</span><strong>Have something suspicious?</strong><p>Paste the complete message for the clearest explanation. No account is required.</p></div>
            <Link className="button primary" href="/"><span className="info-cta-button-label">Open ScamShield</span><span className="info-cta-arrow" aria-hidden="true">→</span></Link>
          </div>
        </article>
      </main>
      <SiteFooter />
    </>
  );
}
