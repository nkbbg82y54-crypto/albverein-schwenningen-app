import assert from "node:assert/strict";
import test from "node:test";
import { createVapidAuthorization, decryptPayload, encryptPayload, validateChangeRequest } from "../src/index.js";

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

test("creates a valid VAPID authorization token", async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const publicKey = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(publicJwk.x, "base64url"),
    Buffer.from(publicJwk.y, "base64url"),
  ]).toString("base64url");
  const authorization = await createVapidAuthorization("https://push.example.test/subscription", {
    VAPID_PRIVATE_JWK: JSON.stringify(privateJwk),
    VAPID_PUBLIC_KEY: publicKey,
    VAPID_SUBJECT: "mailto:test@example.test",
  });
  assert.match(authorization, /^vapid t=[^.]+\.[^.]+\.[^,]+, k=/);
  const token = authorization.slice("vapid t=".length).split(", k=")[0];
  const [header, payload, signature] = token.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  assert.equal(claims.aud, "https://push.example.test");
  assert.equal(claims.sub, "mailto:test@example.test");
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pair.publicKey,
    Buffer.from(signature, "base64url"),
    new TextEncoder().encode(`${header}.${payload}`),
  );
  assert.equal(valid, true);
});
