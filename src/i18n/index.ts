import { readFileSync } from 'node:fs';
import path from 'node:path';
import type { NextFunction, Request, Response } from 'express';
import { ROOT_DIR } from '../config.js';

export const LOCALES = [
  { code: 'en', native: 'English', country: 'ie' },
  { code: 'fr', native: 'Français', country: 'fr' },
  { code: 'es', native: 'Español', country: 'es' },
  { code: 'nl', native: 'Nederlands', country: 'nl' },
  { code: 'de', native: 'Deutsch', country: 'de' },
  { code: 'da', native: 'Dansk', country: 'dk' },
  { code: 'mt', native: 'Malti', country: 'mt' },
  { code: 'sv', native: 'Svenska', country: 'se' },
] as const;

export type LocaleCode = (typeof LOCALES)[number]['code'];
export const DEFAULT_LOCALE: LocaleCode = 'en';
const CODES = new Set<string>(LOCALES.map((l) => l.code));
export const isLocale = (v: unknown): v is LocaleCode => typeof v === 'string' && CODES.has(v);

type Dict = Record<string, string>;
const dictionaries = new Map<LocaleCode, Dict>();

function dictionary(locale: LocaleCode, dir = path.join(ROOT_DIR, 'src', 'i18n', 'locales')): Dict {
  let d = dictionaries.get(locale);
  if (!d) {
    d = JSON.parse(readFileSync(path.join(dir, `${locale}.json`), 'utf8')) as Dict;
    dictionaries.set(locale, d);
  }
  return d;
}

export type Translator = (key: string, vars?: Record<string, string | number>) => string;

/** Translator with English fallback; unknown keys render as the key so gaps are visible, never crash. */
export function translator(locale: LocaleCode): Translator {
  const primary = dictionary(locale);
  const fallback = dictionary(DEFAULT_LOCALE);
  return (key, vars) => {
    const raw = primary[key] ?? fallback[key] ?? key;
    return vars ? raw.replace(/\{(\w+)\}/g, (m, name: string) => (vars[name] !== undefined ? String(vars[name]) : m)) : raw;
  };
}

export function allDictionaries(): Record<LocaleCode, Dict> {
  return Object.fromEntries(LOCALES.map((l) => [l.code, dictionary(l.code)])) as Record<LocaleCode, Dict>;
}

function fromAcceptLanguage(header: string | undefined): LocaleCode | undefined {
  if (!header) return undefined;
  const ranked = header
    .split(',')
    .map((part) => {
      const [tag = '', ...params] = part.trim().split(';');
      const q = Number(params.find((p) => p.trim().startsWith('q='))?.split('=')[1] ?? 1);
      return { lang: tag.toLowerCase().split('-')[0] ?? '', q: Number.isNaN(q) ? 0 : q };
    })
    .filter((x) => x.q > 0)
    .sort((a, b) => b.q - a.q);
  return ranked.map((x) => x.lang).find(isLocale);
}

function cookieValue(req: Request, name: string): string | undefined {
  const raw = req.headers.cookie;
  if (!raw) return undefined;
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return undefined;
}

export function resolveLocale(req: Request): { locale: LocaleCode; fromQuery: boolean } {
  const q = req.query.lang;
  if (isLocale(q)) return { locale: q, fromQuery: true };
  const c = cookieValue(req, 'lang');
  if (isLocale(c)) return { locale: c, fromQuery: false };
  return { locale: fromAcceptLanguage(req.headers['accept-language']) ?? DEFAULT_LOCALE, fromQuery: false };
}

/** Same path + query, with ?lang=<code>; used by the language switcher (keeps the user on the same page). */
function langUrl(req: Request, code: string): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(req.query)) if (k !== 'lang' && typeof v === 'string') params.set(k, v);
  params.set('lang', code);
  return `${req.baseUrl}${req.path}?${params.toString()}`;
}

export function i18nMiddleware(isProduction: boolean) {
  return (req: Request, res: Response, next: NextFunction) => {
    const { locale, fromQuery } = resolveLocale(req);
    if (fromQuery) res.cookie('lang', locale, { maxAge: 365 * 24 * 3600 * 1000, sameSite: 'lax', secure: isProduction, httpOnly: false, path: '/' });
    const intlLocale = locale; // 'mt' is supported by Node's full ICU; falls back to en otherwise
    res.locals.locale = locale;
    res.locals.locales = LOCALES;
    res.locals.t = translator(locale);
    res.locals.langUrl = (code: string) => langUrl(req, code);
    res.locals.fmtDate = (d: string | Date) => new Intl.DateTimeFormat(intlLocale, { dateStyle: 'long' }).format(new Date(d));
    res.locals.fmtMoney = (n: number) => new Intl.NumberFormat(intlLocale, { style: 'currency', currency: 'EUR' }).format(n);
    res.locals.regionName = (code: string) => {
      try {
        return new Intl.DisplayNames([intlLocale], { type: 'region' }).of(code.toUpperCase()) ?? code;
      } catch {
        return code;
      }
    };
    next();
  };
}
