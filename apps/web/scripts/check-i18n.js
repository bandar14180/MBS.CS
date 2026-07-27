// i18n parity check: every locale must have exactly the same key set as en.json.
// Run: node scripts/check-i18n.js
const fs = require("fs");
const path = require("path");

const dir = path.join(__dirname, "..", "locales");
const locales = ["en", "ar", "ms", "fr", "pt", "it", "es"];

function flatten(obj, prefix = "") {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) out.push(...flatten(v, key));
    else out.push(key);
  }
  return out.sort();
}

const dicts = {};
for (const l of locales) {
  dicts[l] = JSON.parse(fs.readFileSync(path.join(dir, `${l}.json`), "utf8"));
}

const enKeys = flatten(dicts.en);
let failures = 0;
for (const l of locales) {
  const keys = flatten(dicts[l]);
  const missing = enKeys.filter((k) => !keys.includes(k));
  const extra = keys.filter((k) => !enKeys.includes(k));
  const empty = keys.filter((k) => {
    const val = k.split(".").reduce((a, p) => a?.[p], dicts[l]);
    return typeof val === "string" && val.trim() === "";
  });
  const ok = missing.length === 0 && extra.length === 0 && empty.length === 0;
  console.log(`${l}: ${keys.length} keys  ${ok ? "OK" : "FAIL"}`);
  if (missing.length) console.log(`   missing: ${missing.join(", ")}`);
  if (extra.length) console.log(`   extra:   ${extra.join(", ")}`);
  if (empty.length) console.log(`   empty:   ${empty.join(", ")}`);
  if (!ok) failures++;
}
console.log(failures === 0 ? `\nALL ${locales.length} LOCALES IN PARITY (${enKeys.length} keys each)` : `\n${failures} locale(s) failed`);
process.exit(failures === 0 ? 0 : 1);
