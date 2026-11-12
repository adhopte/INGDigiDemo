/** Minimal structured logger. Never pass ID tokens, credentials or personal claims to it; sensitive keys are redacted in production as a safety net. */
const SENSITIVE = /token|secret|password|authorization|cookie|claims|verifier|code|given_name|family_name|birth|address|iban|nationality|credential/i;

function scrub(value: unknown, depth = 0): unknown {
  if (depth > 4 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1));
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, SENSITIVE.test(k) ? '[redacted]' : scrub(v, depth + 1)]));
}

type Level = 'info' | 'warn' | 'error';

function emit(level: Level, msg: string, ctx?: Record<string, unknown>) {
  const safe = process.env.NODE_ENV === 'production' || process.env.LOG_REDACT === 'true' ? scrub(ctx) : ctx;
  const line = JSON.stringify({ t: new Date().toISOString(), level, msg, ...(safe as object) });
  (level === 'info' ? console.log : console.error)(line);
}

export const log = {
  info: (msg: string, ctx?: Record<string, unknown>) => emit('info', msg, ctx),
  warn: (msg: string, ctx?: Record<string, unknown>) => emit('warn', msg, ctx),
  error: (msg: string, ctx?: Record<string, unknown>) => emit('error', msg, ctx),
};
