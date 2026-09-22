/**
 * i18n regression: every project tab label must RESOLVE, in every locale.
 *
 * The bug this locks down: the project tab bar grew from 5 to 7 tabs (assets, remediation,
 * risk-assessments), but the `project` namespace in the locale files was never extended. Since
 * t() falls back locale -> English -> the raw key, and English was missing them too, the tab bar
 * rendered the literal strings "project.tabAssets" / "project.tabRemediation" /
 * "project.tabAssessments" to users -- in EVERY locale, not just Arabic.
 *
 * So the assertions here are deliberately NOT a list of expected labels. A hard-coded expectation
 * would have to be edited by the same person who adds the next tab, which is exactly the step that
 * was missed. Instead the test reads the dictionaries directly and asserts the structural property
 * that was violated: for each key the tab bar asks for, every locale returns a non-empty string
 * that is not the key itself.
 *
 * TAB_KEYS is kept in sync with app/(dashboard)/projects/[id]/layout.tsx by the last test, which
 * fails if a tab is added there without being covered here.
 */
import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { LOCALES, type Locale } from "@/lib/i18n";

// NB: aliased with a `dict` prefix because the Italian locale is `it` -- an unprefixed import
// would shadow vitest's `it` and every test in this file would silently fail to register.
import dictAr from "@/locales/ar.json";
import dictEn from "@/locales/en.json";
import dictEs from "@/locales/es.json";
import dictFr from "@/locales/fr.json";
import dictIt from "@/locales/it.json";
import dictMs from "@/locales/ms.json";
import dictPt from "@/locales/pt.json";

const DICTS: Record<Locale, Record<string, unknown>> = {
  en: dictEn,
  ar: dictAr,
  ms: dictMs,
  fr: dictFr,
  pt: dictPt,
  it: dictIt,
  es: dictEs,
};

// The keys the project tab bar passes to t(), in render order.
const TAB_KEYS = [
  "project.tabTargets",
  "project.tabScans",
  "project.tabAssets",
  "project.tabVulnerabilities",
  "project.tabRemediation",
  "project.tabAssessments",
  "project.tabReports",
] as const;

// Mirrors resolve() in lib/i18n.tsx: walk a dotted key, return undefined if any hop is missing.
function resolve(dict: Record<string, unknown>, key: string): unknown {
  return key.split(".").reduce<unknown>((acc, part) => {
    if (acc && typeof acc === "object" && part in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[part];
    }
    return undefined;
  }, dict);
}

describe("project tab translations", () => {
  for (const { code: locale } of LOCALES) {
    it(`${locale} resolves every project tab key to real text`, () => {
      for (const key of TAB_KEYS) {
        const value = resolve(DICTS[locale], key);
        // Present and a string -- not undefined, not an accidentally-nested object.
        expect(value, `${locale}: ${key} is missing`).toBeTypeOf("string");
        // Not blank, and above all not the raw key leaking through as it did before the fix.
        expect((value as string).trim(), `${locale}: ${key} is empty`).not.toBe("");
        expect(value, `${locale}: ${key} renders the raw key`).not.toBe(key);
        expect(value, `${locale}: ${key} renders the raw key`).not.toBe(key.split(".").pop());
      }
    });
  }

  it("gives Arabic the established MBS.SC terminology", () => {
    // These three are the keys that were missing. Pinned because they must reuse the wording
    // already used elsewhere in the app (vulns.remediation, agents.recon.desc) rather than a
    // second synonym for the same concept.
    expect(resolve(dictAr, "project.tabAssets")).toBe("الأصول");
    expect(resolve(dictAr, "project.tabRemediation")).toBe("المعالجة");
    expect(resolve(dictAr, "project.tabAssessments")).toBe("التقييمات");
  });

  it("leaves the pre-existing English tab labels untouched", () => {
    expect(resolve(dictEn, "project.tabTargets")).toBe("Targets");
    expect(resolve(dictEn, "project.tabScans")).toBe("Scans");
    expect(resolve(dictEn, "project.tabVulnerabilities")).toBe("Vulnerabilities");
    expect(resolve(dictEn, "project.tabReports")).toBe("Reports");
    expect(resolve(dictEn, "project.back")).toBe("Projects");
  });

  it("covers every tab the project layout actually renders", () => {
    // Guards against the exact drift that caused the bug: a tab added to the layout but not to
    // the dictionaries. Read the layout source and extract the keys it asks t() for.
    const layout = fs.readFileSync(
      path.join(__dirname, "..", "app", "(dashboard)", "projects", "[id]", "layout.tsx"),
      "utf8"
    );
    const declared = [...layout.matchAll(/key:\s*"(project\.[A-Za-z0-9_]+)"/g)].map((m) => m[1]);

    expect(declared.length).toBeGreaterThan(0);
    expect([...declared].sort()).toEqual([...TAB_KEYS].sort());
  });
});
