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

const BASE64_RE = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,4096}={0,2}(?![A-Za-z0-9+/=])/g;
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
 * re-scanning), recursing up to `depth` to catch double-encoding.
 * Enforces a total budget of 100 decoded blobs to prevent process hanging.
 */
export function findDecodedBlobs(text: string, depth = 2): readonly DecodedBlob[] {
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
      try {
        const decoded = Buffer.from(m[0], "base64").toString("utf8");
        tryAdd(m[0], decoded, "base64", m.index ?? 0);
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
