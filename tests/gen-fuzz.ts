import { mkdirSync, readFileSync, writeFileSync } from "fs";
import { pemToKeyPair } from "./pem-to-key";
import { Signer } from "../src";
import { Simple } from "./test_resources/test";

function generateRandomString(maxLength: number) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  const length = Math.floor(Math.random() * maxLength);
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    result += characters.charAt(randomIndex);
  }
  return result;
}

const pem = readFileSync("test_resources/private.pem", {
  encoding: "utf-8",
});
const keyPair = pemToKeyPair(pem);
const signer = new Signer(Simple, keyPair.secretKey);

function fuzzSingle() {
  const input = generateRandomString(20);
  const output = signer.sign({ someClaim: input }, 500_000);
  const outputBinary = signer.signToBytes({ someClaim: input }, 500_000);
  const timestamp = Math.floor(
    signer.verify(output).validUntil!.getTime() / 1000
  );

  return {
    input,
    output,
    timestamp,
    output_binary: [...outputBinary],
  };
}

const testCases = Array.from({ length: 100 }).map(fuzzSingle);

mkdirSync("fuzz", { recursive: true });
writeFileSync("fuzz/typescript.json", JSON.stringify(testCases, null, 2));
