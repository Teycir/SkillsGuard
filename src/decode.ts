/**
 * Decode-first preprocessing: finds base64/hex/url-encoded blobs in text
 * and decodes them so the pattern engine can match obfuscated payloads,
 * e.g. eval $(echo "Y3VybCAtcyBoOi8v..." | base64 -d)
 */

export interface DecodedBlob {
  readonly raw: string;
  readonly decoded: string;
  readonly encoding: "base64" | "hex" | "url";
  readonly index: number;
}

// Raised minimum from 20 to 32 chars: 20-char alphanumeric tokens (UUIDs
// without hyphens, short hex hashes, version strings) caused too many false
// positives.  32 chars still catches all real base64-encoded payloads while
// filtering the most common noise.
// ponytail: strict base64 alphabet [A-Za-z0-9+/=] only—filters UUIDs/hex hashes
const BASE64_RE = /(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,4096}={0,2})(?![A-Za-z0-9+/=])/g;
const HEX_RE = /(?:\\x[0-9a-fA-F]{2}){6,}|\b[0-9a-fA-F]{32,}\b/g;
const URL_ENC_RE = /(?:%[0-9a-fA-F]{2}){4,}/g;

function isMostlyPrintable(s: string): boolean {
  if (s.length === 0) return false;
  let printable = 0;
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if ((code >= 32 && code < 127) || code === 9 || code === 10 || code === 13) {
      printable++;
    }
  }
  return printable / s.length > 0.85;
}

function decodeHexBlob(raw: string): string | null {
  try {
    const clean = raw.startsWith("\\x") ? raw.replace(/\\x/g, "") : raw;
    if (clean.length % 2 !== 0) return null;
    const buf = Buffer.from(clean, "hex");
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

function decodeUrlBlob(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * Scan a chunk of text for encoded blobs, decode them, and return only the
 * ones that decode to mostly-printable text (real candidates worth
 * re-scanning), recursing up to `depth` to catch multi-layer encoding.
 * Enforces a total budget of 100 decoded blobs to prevent process hanging.
 * ponytail: depth=5 blocks triple/quad-encoding without major perf hit
 */
export function findDecodedBlobs(text: string, depth = 5): readonly DecodedBlob[] {
  const results: DecodedBlob[] = [];
  const seen = new Set<string>();

  function recurse(currentText: string, currentDepth: number): void {
    if (results.length >= 100) return;

    const tryAdd = (raw: string, decoded: string | null, encoding: DecodedBlob["encoding"], index: number) => {
      if (results.length >= 100) return;
      if (!decoded || decoded === raw || seen.has(raw)) return;
      if (!isMostlyPrintable(decoded)) return;
      seen.add(raw);
      results.push({ raw, decoded, encoding, index });
      if (currentDepth > 0) {
        recurse(decoded, currentDepth - 1);
      }
    };

    for (const m of currentText.matchAll(BASE64_RE)) {
      // Valid base64 has a byte-count divisible by 4 (accounting for padding).
      // Filtering here skips hex hashes, UUIDs, and other alphanumeric tokens
      // that happen to be 32+ chars but aren't valid base64.
      const raw = m[0];
      const paddedLen = raw.length + (raw.endsWith("=") ? 0 : (4 - (raw.length % 4)) % 4);
      if (paddedLen % 4 !== 0) continue;
      try {
        const decoded = Buffer.from(raw, "base64").toString("utf8");
        tryAdd(raw, decoded, "base64", m.index ?? 0);
      } catch {
        /* skip */
      }
    }

    for (const m of currentText.matchAll(HEX_RE)) {
      tryAdd(m[0], decodeHexBlob(m[0]), "hex", m.index ?? 0);
    }

    for (const m of currentText.matchAll(URL_ENC_RE)) {
      tryAdd(m[0], decodeUrlBlob(m[0]), "url", m.index ?? 0);
    }
  }

  recurse(text, depth);
  return results;
}
