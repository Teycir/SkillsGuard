import test from "node:test";
import assert from "node:assert";
import { findReportableMatch, toGlobalRegex, MAX_MATCHES_PER_LINE } from "../src/lib/matching.js";

const TEXT = "one two three";
const excuseOneTwo = (text: string) => (index: number, length: number): boolean =>
  text.slice(index, index + length) === "one two";

test("toGlobalRegex: adds g, keeps the other flags, leaves the original untouched", () => {
  const original = /ab+c/im;
  const global = toGlobalRegex(original);
  assert.strictEqual(global.source, original.source);
  assert.ok(global.flags.includes("g") && global.flags.includes("i") && global.flags.includes("m"));
  assert.strictEqual(original.flags.includes("g"), false);
  assert.strictEqual(toGlobalRegex(/x/g).flags, "g", "an already-global regex gains no duplicate flag");
});

test("findReportableMatch: without an excuse it is the plain first match", () => {
  const m = findReportableMatch(toGlobalRegex(/t\w+/), TEXT);
  assert.strictEqual(m?.[0], "two");
  assert.strictEqual(m?.index, 4);
});

test("findReportableMatch: skips excused matches and returns the first one that is not", () => {
  const m = findReportableMatch(toGlobalRegex(/\b\w+\b/), "aa bb cc", (i) => i < 3);
  assert.strictEqual(m?.[0], "bb");
});

test("findReportableMatch: null when every match is excused", () => {
  assert.strictEqual(findReportableMatch(toGlobalRegex(/\w+/), "aa bb", () => true), null);
  assert.strictEqual(findReportableMatch(toGlobalRegex(/zzz/), TEXT, () => true), null, "no match at all");
});

test("findReportableMatch: a real match overlapping an excused one is still found", () => {
  // "one two" is excused. "two three" starts inside it, so resuming at its END would miss it.
  const re = toGlobalRegex(/one two|two three/);
  const m = findReportableMatch(re, TEXT, excuseOneTwo(TEXT));
  assert.strictEqual(m?.[0], "two three");
});

test("findReportableMatch: fails closed once a line has more matches than the cap", () => {
  const text = "a".repeat(MAX_MATCHES_PER_LINE + 50);
  const m = findReportableMatch(toGlobalRegex(/a/), text, () => true);
  assert.notStrictEqual(m, null, "a pathological line must be reported, not silenced");
  assert.strictEqual(m?.index, MAX_MATCHES_PER_LINE - 1);
});

test("findReportableMatch: zero-length matches always terminate", () => {
  assert.strictEqual(findReportableMatch(toGlobalRegex(/(?:)/), "abc", () => true), null);
});

test("findReportableMatch: leaves lastIndex at 0 so the regex can be reused", () => {
  const re = toGlobalRegex(/a/);
  findReportableMatch(re, "aaa", (i) => i === 0);
  assert.strictEqual(re.lastIndex, 0);
  assert.strictEqual(findReportableMatch(re, "aaa")?.index, 0, "second use starts from the beginning");
});

test("findReportableMatch: an excuse that throws propagates and still resets lastIndex", () => {
  const re = toGlobalRegex(/a/);
  assert.throws(() => findReportableMatch(re, "aaa", () => { throw new Error("boom"); }), /boom/);
  assert.strictEqual(re.lastIndex, 0);
});
