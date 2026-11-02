/**
 * SkillsGuard — classify files by what they ARE, not what they are called.
 *
 * A name says nothing about content: `ctypes.CDLL("README.txt")` and `import`
 * load an ELF with any suffix, and a shell script needs no extension. Deciding
 * what to read from the filename alone is the same mistake as skipping
 * __pycache__ — the code that actually runs is removed before analysis — so
 * the scanner also looks at the first bytes of a file.
 */

import { open } from "node:fs/promises";

/** Extensions that name a loadable binary module. Reported even if the header is unrecognised. */
export const NATIVE_EXTENSIONS: ReadonlySet<string> = new Set([
  ".so", ".pyd", ".dll", ".dylib", ".node", ".wasm", ".exe",
]);

/** Extensions a runtime or shell executes as source. */
export const SCRIPT_EXTENSIONS: ReadonlySet<string> = new Set([
  ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
  ".sh", ".bash", ".zsh", ".fish", ".ksh",
  ".ps1", ".psm1", ".psd1",
  ".rb", ".rake",
]);

/** Bytes read from the start of a file. Enough for every magic number and the PE header pointer. */
export const SNIFF_BYTES = 64;

const at = (b: Uint8Array, i: number): number => b[i] ?? -1;

/**
 * Name the binary format a header belongs to, or null if it is not a known
 * executable/loadable format. `totalSize` is the size of the whole file; it is
 * used to tell a real PE (header pointer lands inside the file) from a text
 * file that merely starts with "MZ".
 */
export function detectBinaryFormat(head: Uint8Array, totalSize: number): string | null {
  if (head.length < 4) return null;
  const [b0, b1, b2, b3] = [at(head, 0), at(head, 1), at(head, 2), at(head, 3)];

  if (b0 === 0x7f && b1 === 0x45 && b2 === 0x4c && b3 === 0x46) return "ELF";
  if (b0 === 0x00 && b1 === 0x61 && b2 === 0x73 && b3 === 0x6d) return "WebAssembly";

  if (
    (b0 === 0xfe && b1 === 0xed && b2 === 0xfa && (b3 === 0xce || b3 === 0xcf)) ||
    (b3 === 0xfe && b2 === 0xed && b1 === 0xfa && (b0 === 0xce || b0 === 0xcf))
  ) {
    return "Mach-O";
  }
  // 0xCAFEBABE is shared by Mach-O universal binaries and Java class files; both are opaque code.
  if (b0 === 0xca && b1 === 0xfe && b2 === 0xba && b3 === 0xbe) return "Mach-O universal / Java class";

  if (b0 === 0x4d && b1 === 0x5a && head.length >= 0x40) {
    // e_lfanew: little-endian offset of the PE header, stored at 0x3C.
    const lfanew =
      (at(head, 0x3c) | (at(head, 0x3d) << 8) | (at(head, 0x3e) << 16) | (at(head, 0x3f) << 24)) >>> 0;
    if (lfanew >= 0x40 && lfanew + 4 <= totalSize) return "PE (Windows)";
  }
  return null;
}

/** True when the header starts with a `#!` interpreter line. */
export function hasShebang(head: Uint8Array): boolean {
  return head.length >= 2 && head[0] === 0x23 && head[1] === 0x21;
}

export interface FileSniff {
  /** Detected binary format, or null. */
  readonly format: string | null;
  readonly shebang: boolean;
  readonly size: number;
}

/**
 * Read the header of a regular file. Callers must not pass FIFOs, sockets or
 * devices: opening a FIFO for reading blocks until a writer appears.
 */
export async function sniffFile(path: string): Promise<FileSniff> {
  const handle = await open(path, "r");
  try {
    const { size } = await handle.stat();
    const buf = Buffer.alloc(SNIFF_BYTES);
    const { bytesRead } = await handle.read(buf, 0, SNIFF_BYTES, 0);
    const head = buf.subarray(0, bytesRead);
    return { format: detectBinaryFormat(head, size), shebang: hasShebang(head), size };
  } finally {
    await handle.close();
  }
}
