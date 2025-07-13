import { base64decode, IMessageType } from "@protobuf-ts/runtime";
import { TokenData } from "./types.js";
import { Decoder } from "./decoder.js";

export class Verifier<T extends object> extends Decoder<T> {
  #publicKey: Uint8Array;
  constructor(codec: IMessageType<T>, publicKey: Uint8Array) {
    super(codec);
    this.#publicKey = publicKey;
  }

  async verify(token: string): Promise<TokenData<T>> {
    const [base64Data, base64Signature] = token.split(".");
    const data = base64decode(base64Data);
    const signature = base64decode(base64Signature);

    const isValid = await (
      await import("@noble/ed25519")
    ).verifyAsync(signature, data, this.#publicKey);
    if (!isValid) {
      throw new Error("Invalid signature!");
    }

    return this.fromBinaryData(data);
  }

  async verifyAndCheckExpiry(token: string): Promise<T> {
    const [base64Data, base64Signature] = token.split(".");
    const data = base64decode(base64Data);
    const signature = base64decode(base64Signature);
    const isValid = await (
      await import("@noble/ed25519")
    ).verifyAsync(signature, data, this.#publicKey);
    if (!isValid) {
      throw new Error("Invalid signature!");
    }
    const tokenData = this.fromBinaryData(data);
    if (tokenData.validUntil && tokenData.validUntil <= new Date()) {
      throw new Error("Token expired");
    }
    return tokenData.claims;
  }
}
