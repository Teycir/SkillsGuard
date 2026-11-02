import test from "node:test";
import assert from "node:assert";
import { lstatSync, readdirSync, readlinkSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The Cloudflare worker must run the SAME scanner as the CLI. Every file under
 * worker/src is a symlink into src/, except the worker's own entry point. A copy
 * drifts: the worker once kept importing a placeholder filter that had been
 * removed for being bypassable, so it would not even compile. These tests fail the
 * moment anyone replaces a link with a copy or leaves a dangling one.
 */

// dist-test/tests/<this file>.js  ->  repository root
const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const WORKER_SRC = join(ROOT, "worker", "src");
const SRC = realpathSync(join(ROOT, "src"));

/** Files that belong to the worker alone and are not mirrored from src/. */
const WORKER_OWN_FILES: ReadonlySet<string> = new Set(["worker.ts"]);

/** Every file or symlink under `dir`. A symlinked directory is reported as itself, not entered. */
function* entries(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* entries(path);
    else yield path;
  }
}

/** The real path of a mirrored entry, or a failed assertion that names the broken link. */
function resolveMirror(path: string): string {
  try {
    return realpathSync(path);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    assert.fail(`${relative(ROOT, path)} is a dangling or unreadable link: ${reason}`);
  }
}

test("worker/src mirrors src/ through symlinks, never through copies", () => {
  let checked = 0;
  for (const path of entries(WORKER_SRC)) {
    const name = relative(WORKER_SRC, path);
    if (WORKER_OWN_FILES.has(name)) continue;
    assert.ok(
      lstatSync(path).isSymbolicLink(),
      `worker/src/${name} is a copy; it must be a symlink into src/ or it will drift`,
    );
    const target = resolveMirror(path);
    assert.ok(
      target.startsWith(SRC + sep),
      `worker/src/${name} points outside src/: ${target}`,
    );
    // An absolute link resolves on the machine that made it and dangles on every other
    // clone (CI, a deploy from another laptop), so a passing realpath is not enough.
    assert.ok(
      !isAbsolute(readlinkSync(path)),
      `worker/src/${name} is an absolute link (${readlinkSync(path)}); make it relative`,
    );
    checked++;
  }
  assert.ok(checked >= 10, `expected a mirrored tree, found only ${checked} links`);
});

test("the worker scans with the CLI's scanner and its placeholder logic", () => {
  for (const file of ["scanner.ts", "lib/placeholder.ts", "lib/matching.ts", "rules/network.ts"]) {
    assert.strictEqual(
      resolveMirror(join(WORKER_SRC, file)),
      realpathSync(join(SRC, file)),
      `worker/src/${file} is not the same file as src/${file}`,
    );
  }
});
