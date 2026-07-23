"use client";

import Link from "next/link";
import { useEffect, useSyncExternalStore } from "react";

const THEME_STORAGE_KEY = "scamshield-theme";
const THEME_CHANGE_EVENT = "scamshield-theme-change";

type Theme = "light" | "dark";

const navigation = [
  { href: "/how-it-works", label: "How it works" },
  { href: "/methodology", label: "Methodology" },
  { href: "/privacy", label: "Privacy" },
  { href: "/limitations", label: "Limitations" },
];

export function ScamShieldLogoMark({ className = "" }: { className?: string }) {
  return <span className={`m2-logo ${className}`.trim()} aria-hidden="true" />;
}

function getThemeSnapshot(): Theme {
  const savedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (savedTheme === "dark" || savedTheme === "light") return savedTheme;
  return "dark";
}

function subscribeToTheme(onStoreChange: () => void) {
  window.addEventListener("storage", onStoreChange);
  window.addEventListener(THEME_CHANGE_EVENT, onStoreChange);
  return () => {
    window.removeEventListener("storage", onStoreChange);
    window.removeEventListener(THEME_CHANGE_EVENT, onStoreChange);
  };
}

export function SiteHeader({ activePath }: { activePath?: string }) {
  const theme = useSyncExternalStore(subscribeToTheme, getThemeSnapshot, () => "dark");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  function toggleTheme() {
    const nextTheme = theme === "dark" ? "light" : "dark";
    window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
  }

  return (
    <header className="site-header">
      <Link className="brand" href="/" aria-label="ScamShield home">
        <span className="brand-mark" aria-hidden="true"><ScamShieldLogoMark /></span>
        <span className="brand-name">SCAMSHIELD</span>
      </Link>
      <nav aria-label="Main navigation">
        {navigation.map((item) => (
          <Link key={item.href} href={item.href} className={activePath === item.href ? "active" : ""} aria-current={activePath === item.href ? "page" : undefined}>
            {item.label}
          </Link>
        ))}
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

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div>
        <span className="footer-brand">SCAMSHIELD</span>
        <p>Explainable scam triage for suspicious messages and links.</p>
      </div>
      <p>A risk estimate is not a guarantee. For money, credentials, or identity documents, verify through an official channel you find independently.</p>
    </footer>
  );
}
