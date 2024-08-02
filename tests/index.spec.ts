import assert from "node:assert";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import rustFuzz from "../fuzz/rust.json";
import { Decoder, Signer, Verifier } from "../src/index";
import { pemToKeyPair } from "./pem-to-key";
import { Simple } from "./test_resources/test";

describe("pwt", () => {
  const pem = readFileSync("test_resources/private.pem", {
    encoding: "utf-8",
  });
  const keyPair = pemToKeyPair(pem);

  it("works for an example", () => {
    const verifier = new Verifier(Simple, keyPair.publicKey);

    const { claims, validUntil } = verifier.verify(
      "CgsImpnrqQYQzMKlCRIPEg10ZXN0IGNvbnRlbnRz.gNAqudBxRzCSbwjIYGhvVgWuhUk17BBoXgZk-uqKNVXRfXQZ2qDvG-4I-BRDkxJTKYlwgEATeEplbv7idBVFBA"
    );
    assert.deepStrictEqual({ ...claims }, { someClaim: "test contents" });
    assert.strictEqual(validUntil?.getTime(), 1698352282020);
  });

  it("can decode its own tokens", () => {
    const signer = new Signer(Simple, keyPair.secretKey);
    const someClaim =
      "testsfaosiqwF121413513   928RT938TG  Q93GQW3Q73BG8QW7BVQ8A37VBQ938QB983BVQ _-sdgae/aw=";
    const token = signer.sign(
      {
        someClaim,
      },
      1000
    );
    const claims = signer.verifyAndCheckExpiry(token);
    assert.strictEqual(claims.someClaim, someClaim);
  });

  it("checks expiry correctly", async () => {
    const signer = new Signer(Simple, keyPair.secretKey);
    const someClaim = "test";
    const token = signer.sign(
      {
        someClaim,
      },
      100
    );
    await new Promise((res) => setTimeout(res, 100));
    assert.throws(() => signer.verifyAndCheckExpiry(token));
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
