import crypto from "node:crypto";
import * as ed25519 from "@noble/ed25519";

export async function pemToKeyPair(pem: string): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const cryptoPK = crypto.createPrivateKey({
    key: pem,
    format: "pem",
  });
  const buf = cryptoPK.export({ format: "der", type: "pkcs8" });
  const privateKey = new Uint8Array(buf).slice(buf.length - 32);
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  return { publicKey, privateKey };
}
