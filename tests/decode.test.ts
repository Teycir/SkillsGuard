import test from "node:test";
import assert from "node:assert";
import { findDecodedBlobs } from "../src/decode.js";

test("findDecodedBlobs decodes valid base64", () => {
  // "aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBsb25nZXIgc3RyaW5nIHRoYXQgd2lsbCBlbmNvZGUgdG8gbW9yZSB0aGFuIDIwIGJhc2U2NCBjaGFycw=="
  // is base64 for "hello world, this is a longer string that will encode to more than 20 base64 chars"
  const text = "Prefix aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBsb25nZXIgc3RyaW5nIHRoYXQgd2lsbCBlbmNvZGUgdG8gbW9yZSB0aGFuIDIwIGJhc2U2NCBjaGFycw== suffix";
  const blobs = findDecodedBlobs(text);
  assert.strictEqual(blobs.length, 1);
  assert.strictEqual(blobs[0]?.encoding, "base64");
  assert.ok(blobs[0]?.decoded.includes("hello world"));
});

test("findDecodedBlobs respects depth limit", () => {
  // Double-encoded "hello world, this is a longer string that will encode to more than 20 base64 chars"
  const text = "YUdWc2JHOGdkMjl5YkdRc0lIUm9hWE1nYVhNZ1lTQnNiMjVuWlhJZ2MzUnlhVzVuSUhSb1lYUWdkMmxzYkNCbGJtTnZaR1VnZEc4Z2JXOXlaU0IwYUdGdUlESXdJR0poYzJVMk5DQmphR0Z5Y3c9PQ==";
  const blobs = findDecodedBlobs(text, 2);
  assert.ok(blobs.length >= 2);
  assert.ok(blobs.some((b) => b.decoded.includes("hello world")));
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
