import crypto from "node:crypto";
import nacl from "tweetnacl";
import { SignKeyPair } from "tweetnacl";

export function pemToKeyPair(pem: string): SignKeyPair {
  const cryptoPK = crypto.createPrivateKey({
    key: pem,
    format: "pem",
  });
  const buf = cryptoPK.export({ format: "der", type: "pkcs8" });
  const seed = new Uint8Array(buf).slice(buf.length - 32);
  return nacl.sign.keyPair.fromSeed(seed);
}
