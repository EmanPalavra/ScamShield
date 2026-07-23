"use client";

import { createContext, useContext, useEffect, useMemo, useSyncExternalStore, type ReactNode } from "react";
import { isLocale, translateText, type Locale } from "./translations";

const STORAGE_KEY = "scamshield-language";
const LANGUAGE_EVENT = "scamshield-language-change";
type TranslationSource = { source: string; lastApplied: string };

const textSources = new WeakMap<Text, TranslationSource>();
const attributeSources = new WeakMap<Element, Map<string, TranslationSource>>();
const translatableAttributes = ["aria-label", "title", "placeholder"] as const;

interface LanguageContextValue {
  locale: Locale;
  setLocale(locale: Locale): void;
  t(value: string): string;
}

const LanguageContext = createContext<LanguageContextValue>({
  locale: "en",
  setLocale: () => undefined,
  t: (value) => value,
});

function getLocaleSnapshot(): Locale {
  const saved = window.localStorage.getItem(STORAGE_KEY);
  if (isLocale(saved)) return saved;
  const browserLocale = window.navigator.language.toLowerCase().split("-")[0];
  return isLocale(browserLocale) ? browserLocale : "en";
}

function subscribeToLocale(onStoreChange: () => void) {
  window.addEventListener("storage", onStoreChange);
  window.addEventListener(LANGUAGE_EVENT, onStoreChange);
  return () => {
    window.removeEventListener("storage", onStoreChange);
    window.removeEventListener(LANGUAGE_EVENT, onStoreChange);
  };
}

function translateNode(root: Node, locale: Locale) {
  const textNodes: Text[] = root.nodeType === Node.TEXT_NODE ? [root as Text] : [];
  if (root.nodeType !== Node.TEXT_NODE) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) textNodes.push(walker.currentNode as Text);
  }

  for (const node of textNodes) {
    const parent = node.parentElement;
    if (!parent || parent.closest("[data-i18n-skip], script, style, code, pre")) continue;
    const current = node.nodeValue ?? "";
    const stored = textSources.get(node);
    const record = stored && current === stored.lastApplied ? stored : { source: current, lastApplied: current };
    const translated = translateText(record.source, locale);
    record.lastApplied = translated;
    textSources.set(node, record);
    if (node.nodeValue !== translated) node.nodeValue = translated;
  }

  const elements = root instanceof Element ? [root, ...root.querySelectorAll("*")] : [];
  for (const element of elements) {
    if (element.closest("[data-i18n-skip]")) continue;
    const stored = attributeSources.get(element) ?? new Map<string, TranslationSource>();
    for (const attribute of translatableAttributes) {
      const current = element.getAttribute(attribute);
      if (!current) continue;
      const previous = stored.get(attribute);
      const record = previous && current === previous.lastApplied ? previous : { source: current, lastApplied: current };
      const translated = translateText(record.source, locale);
      record.lastApplied = translated;
      stored.set(attribute, record);
      if (translated !== current) element.setAttribute(attribute, translated);
    }
    attributeSources.set(element, stored);
  }
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const locale = useSyncExternalStore<Locale>(subscribeToLocale, getLocaleSnapshot, (): Locale => "en");

  useEffect(() => {
    document.documentElement.lang = locale;
    translateNode(document.body, locale);
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === "characterData") {
          translateNode(mutation.target, locale);
        } else if (mutation.type === "attributes") {
          translateNode(mutation.target, locale);
        } else {
          mutation.addedNodes.forEach((node) => translateNode(node, locale));
        }
      }
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: [...translatableAttributes],
    });
    return () => observer.disconnect();
  }, [locale]);

  const value = useMemo<LanguageContextValue>(() => ({
    locale,
    setLocale(nextLocale) {
      window.localStorage.setItem(STORAGE_KEY, nextLocale);
      window.dispatchEvent(new Event(LANGUAGE_EVENT));
    },
    t(valueToTranslate) {
      return translateText(valueToTranslate, locale);
    },
  }), [locale]);

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  return useContext(LanguageContext);
}
