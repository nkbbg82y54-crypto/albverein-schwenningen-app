import assert from "node:assert/strict";
import test from "node:test";
import { decryptPayload, encryptPayload, validateChangeRequest } from "../src/index.js";

test("encrypts and decrypts a change request payload", async () => {
  const key = Buffer.alloc(32, 7).toString("base64");
  const payload = { memberNumber: "12345", iban: "DE00123456789012345678" };
  const encrypted = await encryptPayload(payload, key);

  assert.notEqual(encrypted.ciphertext, JSON.stringify(payload));
  assert.equal(Buffer.from(encrypted.iv, "base64").length, 12);
  assert.deepEqual(await decryptPayload(encrypted.ciphertext, encrypted.iv, key), payload);
});

test("normalizes a valid German IBAN", () => {
  const result = validateChangeRequest({
    requestType: "bank",
    payload: {
      name: "Max Mustermann",
      memberNumber: "12345",
      accountHolder: "Max Mustermann",
      iban: "DE00 1234 5678 9012 3456 78",
    },
  });

  assert.equal(result.payload.iban, "DE00123456789012345678");
});

test("rejects malformed change requests", () => {
  assert.throws(
    () => validateChangeRequest({ requestType: "bank", payload: { iban: "invalid" } }),
    /Invalid field/,
  );
});
