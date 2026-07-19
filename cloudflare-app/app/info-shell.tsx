import Link from "next/link";
import type { ReactNode } from "react";

export function InfoShell({
  eyebrow,
  title,
  intro,
  children,
}: {
  eyebrow: string;
  title: string;
  intro: string;
  children: ReactNode;
}) {
  return (
    <>
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
        </nav>
      </header>
      <main className="info-main">
        <article className="info-page">
          <div className="info-hero">
            <p className="eyebrow">{eyebrow}</p>
            <h1>{title}</h1>
            <p>{intro}</p>
          </div>
          <div className="info-content">{children}</div>
          <div className="info-cta">
            <div><strong>Have something suspicious?</strong><p>Run a check without creating an account.</p></div>
            <Link className="button primary" href="/">Open ScamShield</Link>
          </div>
        </article>
      </main>
      <footer className="site-footer">
        <div><span className="footer-brand">SCAMSHIELD</span><p>Explainable scam triage for suspicious messages and links.</p></div>
        <p>A risk estimate is not a guarantee. Always verify high-impact requests through an official channel.</p>
      </footer>
    </>
  );
}
