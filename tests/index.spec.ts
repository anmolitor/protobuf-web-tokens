import assert from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import rustFuzz from "../fuzz/rust.json";
import { Decoder, Signer, Verifier } from "../src/index";
import { pemToKeyPair } from "./pem-to-key";
import { Simple } from "./test_resources/test";
import crypto from "node:crypto";
import * as ed25519 from "@noble/ed25519";

globalThis.crypto = crypto as any;

describe("pwt", async () => {
  const pem = readFileSync("test_resources/private.pem", {
    encoding: "utf-8",
  });
  const keyPair = await pemToKeyPair(pem);

  it("works for an example", async () => {
    const verifier = new Verifier(Simple, keyPair.publicKey);

    const { claims, validUntil } = await verifier.verify(
      "CgsImpnrqQYQzMKlCRIPEg10ZXN0IGNvbnRlbnRz.gNAqudBxRzCSbwjIYGhvVgWuhUk17BBoXgZk-uqKNVXRfXQZ2qDvG-4I-BRDkxJTKYlwgEATeEplbv7idBVFBA"
    );
    assert.deepStrictEqual({ ...claims }, { someClaim: "test contents" });
    assert.strictEqual(validUntil?.getTime(), 1698352282020);
  });

  it("can decode its own tokens", async () => {
    const signer = new Signer(Simple, keyPair);
    const someClaim =
      "testsfaosiqwF121413513   928RT938TG  Q93GQW3Q73BG8QW7BVQ8A37VBQ938QB983BVQ _-sdgae/aw=";
    const token = await signer.sign(
      {
        someClaim,
      },
      1000
    );
    const claims = await signer.verifyAndCheckExpiry(token);
    assert.strictEqual(claims.someClaim, someClaim);
  });

  it("checks expiry correctly", async () => {
    const signer = new Signer(Simple, keyPair);
    const someClaim = "test";
    const token = await signer.sign(
      {
        someClaim,
      },
      100
    );
    await new Promise((res) => setTimeout(res, 100));
    await assert.rejects(() => signer.verifyAndCheckExpiry(token));
  });

  describe("works for rust generated fuzzed tokens", () => {
    rustFuzz.forEach(({ input, output, timestamp }) => {
      const { claims, validUntil } = new Decoder(Simple).decode(output);
      assert.strictEqual(claims.someClaim, input);
      const validUntilInSeconds = Math.floor(validUntil!.getTime() / 1000);
      assert.strictEqual(validUntilInSeconds, timestamp);
    });
  });
});
