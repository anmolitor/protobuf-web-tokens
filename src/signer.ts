import { base64encode, IMessageType } from "@protobuf-ts/runtime";
import { Timestamp } from "./google/protobuf/timestamp.js";
import { SignedToken, Token } from "./pwt.js";
import { KeyPair } from "./types.js";
import { Verifier } from "./verifier.js";

export class Signer<T extends object> extends Verifier<T> {
  #privateKey: Uint8Array;
  constructor(codec: IMessageType<T>, keyPair: KeyPair) {
    super(codec, keyPair.publicKey);
    this.#privateKey = keyPair.privateKey;
  }

  async sign(claims: T, validForMilliseconds: number): Promise<string> {
    const encodedClaims = this.codec.toBinary(claims);
    const validUntil = new Date().getTime() + validForMilliseconds;
    const tokenData = Token.toBinary({
      claims: encodedClaims,
      validUntil: Timestamp.fromDate(new Date(validUntil)),
    });
    const signature = await (
      await import("@noble/ed25519")
    ).signAsync(tokenData, this.#privateKey);
    return (
      urlSafeBase64Encode(tokenData) + "." + urlSafeBase64Encode(signature)
    );
  }

  async signToBytes(
    claims: T,
    validForMilliseconds: number
  ): Promise<Uint8Array> {
    const encodedClaims = this.codec.toBinary(claims);
    const validUntil = new Date().getTime() + validForMilliseconds;
    const data = Token.toBinary({
      claims: encodedClaims,
      validUntil: Timestamp.fromDate(new Date(validUntil)),
    });
    const signature = await (
      await import("@noble/ed25519")
    ).signAsync(data, this.#privateKey);
    return SignedToken.toBinary({ signature, data });
  }
}

function urlSafeBase64Encode(bytes: Uint8Array) {
  const base64 = base64encode(bytes);
  return base64.replace(/\//g, "_").replace(/\+/g, "-").replace(/=+$/, "");
}
