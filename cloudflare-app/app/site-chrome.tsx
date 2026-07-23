"use client";

import Link from "next/link";
import { useEffect, useRef, useSyncExternalStore } from "react";
import { useLanguage } from "./i18n";
import { supportedLocales } from "./translations";

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

function LanguageFlag({ code }: { code: (typeof supportedLocales)[number]["code"] }) {
  const common = { className: "language-flag", viewBox: "0 0 24 16", "aria-hidden": true, focusable: false } as const;

  if (code === "en") return (
    <svg {...common}>
      <rect width="24" height="16" fill="#173f7a" />
      <path d="M0 0 24 16M24 0 0 16" stroke="#fff" strokeWidth="4" />
      <path d="M0 0 24 16M24 0 0 16" stroke="#d52b1e" strokeWidth="1.5" />
      <path d="M12 0v16M0 8h24" stroke="#fff" strokeWidth="5" />
      <path d="M12 0v16M0 8h24" stroke="#d52b1e" strokeWidth="2.6" />
    </svg>
  );
  if (code === "bs") return (
    <svg {...common}>
      <rect width="24" height="16" fill="#1854a4" />
      <path d="M7 1h10v14z" fill="#f4d43c" />
      <path d="M5 1.5h1.4M6.5 4h1.4M8 6.5h1.4M9.5 9h1.4M11 11.5h1.4M12.5 14h1.4" stroke="#fff" strokeWidth="1.2" />
    </svg>
  );
  if (code === "hr") return (
    <svg {...common}>
      <path d="M0 0h24v5.34H0z" fill="#e43b3b" /><path d="M0 5.33h24v5.34H0z" fill="#fff" /><path d="M0 10.66h24V16H0z" fill="#24539a" />
      <path d="M10 5.3h4v4.6h-4z" fill="#fff" stroke="#d92f36" strokeWidth=".4" /><path d="M10 5.3h1.33v1.5H10zm2.67 0H14v1.5h-1.33zm-1.34 1.5h1.34v1.5h-1.34zM10 8.3h1.33v1.6H10zm2.67 0H14v1.6h-1.33z" fill="#d92f36" />
    </svg>
  );
  if (code === "sr") return (
    <svg {...common}>
      <path d="M0 0h24v5.34H0z" fill="#d9363e" /><path d="M0 5.33h24v5.34H0z" fill="#244b8f" /><path d="M0 10.66h24V16H0z" fill="#fff" />
      <path d="M7 4.3h4v5.5l-2 1-2-1z" fill="#fff" stroke="#d9ad36" strokeWidth=".5" /><path d="M7.5 5h3v1.2h-3z" fill="#d9363e" />
    </svg>
  );
  if (code === "de") return <svg {...common}><path d="M0 0h24v5.34H0z" /><path d="M0 5.33h24v5.34H0z" fill="#d62f3a" /><path d="M0 10.66h24V16H0z" fill="#f5ca38" /></svg>;
  if (code === "es") return <svg {...common}><path d="M0 0h24v4H0zM0 12h24v4H0z" fill="#c92d35" /><path d="M0 4h24v8H0z" fill="#f4c441" /></svg>;
  if (code === "fr") return <svg {...common}><path d="M0 0h8v16H0z" fill="#2451a4" /><path d="M8 0h8v16H8z" fill="#fff" /><path d="M16 0h8v16h-8z" fill="#e33b45" /></svg>;
  return <svg {...common}><path d="M0 0h24v5.34H0z" fill="#d63b43" /><path d="M0 5.33h24v5.34H0z" fill="#fff" /><path d="M0 10.66h24V16H0z" fill="#264e91" /></svg>;
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
  const { locale, setLocale, t } = useLanguage();
  const languageMenuRef = useRef<HTMLDetailsElement>(null);
  const currentLanguage = supportedLocales.find((option) => option.code === locale) ?? supportedLocales[0];

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    function closeLanguageMenu(event: PointerEvent) {
      if (!languageMenuRef.current?.contains(event.target as Node)) languageMenuRef.current?.removeAttribute("open");
    }

    function closeLanguageMenuWithKeyboard(event: KeyboardEvent) {
      if (event.key === "Escape") {
        languageMenuRef.current?.removeAttribute("open");
        languageMenuRef.current?.querySelector("summary")?.focus();
      }
    }

    document.addEventListener("pointerdown", closeLanguageMenu);
    document.addEventListener("keydown", closeLanguageMenuWithKeyboard);
    return () => {
      document.removeEventListener("pointerdown", closeLanguageMenu);
      document.removeEventListener("keydown", closeLanguageMenuWithKeyboard);
    };
  }, []);

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
        <details className="language-picker" ref={languageMenuRef} data-i18n-skip>
          <summary aria-label={`Language: ${currentLanguage.label}`} title={currentLanguage.label}>
            <LanguageFlag code={currentLanguage.code} />
            <strong>{currentLanguage.short}</strong>
            <span className="language-chevron" aria-hidden="true" />
          </summary>
          <div className="language-menu" role="menu" aria-label="Choose language">
            <div className="language-menu-title">Language</div>
            {supportedLocales.map((option) => (
              <button
                key={option.code}
                type="button"
                role="menuitemradio"
                aria-checked={locale === option.code}
                className={locale === option.code ? "active" : ""}
                onClick={() => {
                  setLocale(option.code);
                  languageMenuRef.current?.removeAttribute("open");
                }}
              >
                <LanguageFlag code={option.code} />
                <span><strong>{option.label}</strong><small>{option.short}</small></span>
                <i aria-hidden="true">✓</i>
              </button>
            ))}
          </div>
        </details>
        <button
          className="theme-toggle"
          type="button"
          data-i18n-skip
          data-current-theme={theme}
          onClick={toggleTheme}
          aria-label={t(`Switch to ${theme === "dark" ? "light" : "dark"} mode`)}
          title={t(`Switch to ${theme === "dark" ? "light" : "dark"} mode`)}
        >
          <span className="theme-toggle-icon" aria-hidden="true">
            <svg className="theme-icon theme-icon-sun" viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="3.5" />
              <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M18.7 5.3l-1.4 1.4M6.7 17.3l-1.4 1.4" />
            </svg>
            <svg className="theme-icon theme-icon-moon" viewBox="0 0 24 24">
              <path d="M19.2 15.2A8 8 0 0 1 8.8 4.8 8.1 8.1 0 1 0 19.2 15.2Z" />
            </svg>
          </span>
          <span className="theme-toggle-label">{t(theme === "dark" ? "Light" : "Dark")}</span>
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
