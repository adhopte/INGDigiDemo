// Verifies that every translation key used in views/src exists in en.json, and that all locales have the same keys and placeholders.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
const root = new URL('..', import.meta.url).pathname;
const dir = join(root, 'src/i18n/locales');
const en = JSON.parse(readFileSync(join(dir, 'en.json'), 'utf8'));
let bad = 0;
const files = readdirSync(dir).filter((f) => f.endsWith('.json') && f !== 'en.json');
const ph = (s) => (s.match(/\{\w+\}/g) ?? []).sort().join(',');
for (const f of files) {
  const d = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  for (const k of Object.keys(en)) {
    if (!(k in d)) { console.log(`${f}: missing ${k}`); bad++; }
    else if (ph(d[k]) !== ph(en[k])) { console.log(`${f}: placeholder mismatch ${k}`); bad++; }
  }
  for (const k of Object.keys(d)) if (!(k in en)) { console.log(`${f}: extra ${k}`); bad++; }
}
console.log(bad ? `${bad} problem(s)` : `i18n OK (${Object.keys(en).length} keys, ${files.length + 1} locales)`);
process.exit(bad ? 1 : 0);
