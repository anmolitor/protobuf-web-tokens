import { base64decode, base64encode, IMessageType } from "@protobuf-ts/runtime";
import { SignedToken, Token } from "./pwt.js";
import { Timestamp } from "./google/protobuf/timestamp.js";
import nacl from "tweetnacl";

export interface TokenData<T> {
  claims: T;
  validUntil?: Date;
}

export class Decoder<T extends object> {
  constructor(protected readonly codec: IMessageType<T>) {}

  decode(token: string): TokenData<T> {
    const [base64Data] = token.split(".");
    const data = base64decode(base64Data);

    return this.fromBinaryData(data);
  }

  protected fromBinaryData(data: Uint8Array): TokenData<T> {
    const tokenData = Token.fromBinary(data);

    const claims = this.codec.fromBinary(tokenData.claims);
    const validUntil =
      tokenData.validUntil && Timestamp.toDate(tokenData.validUntil);

    return { claims, validUntil };
  }
}

export class Verifier<T extends object> extends Decoder<T> {
  constructor(codec: IMessageType<T>, private readonly publicKey: Uint8Array) {
    super(codec);
  }

  verify(token: string): TokenData<T> {
    const [base64Data, base64Signature] = token.split(".");
    const data = base64decode(base64Data);
    const signature = base64decode(base64Signature);
    if (!nacl.sign.detached.verify(data, signature, this.publicKey)) {
      throw new Error("Invalid signature!");
    }

    return this.fromBinaryData(data);
  }

  verifyAndCheckExpiry(token: string): T {
    const [base64Data, base64Signature] = token.split(".");
    const data = base64decode(base64Data);
    const signature = base64decode(base64Signature);
    if (!nacl.sign.detached.verify(data, signature, this.publicKey)) {
      throw new Error("Invalid signature!");
    }
    const tokenData = this.fromBinaryData(data);
    if (tokenData.validUntil && tokenData.validUntil <= new Date()) {
      throw new Error("Token expired");
    }
    return tokenData.claims;
  }
}

export class Signer<T extends object> extends Verifier<T> {
  constructor(codec: IMessageType<T>, private readonly privateKey: Uint8Array) {
    super(codec, privateKey.slice(privateKey.length - 32));
  }

  sign(claims: T, validForMilliseconds: number): string {
    const encodedClaims = this.codec.toBinary(claims);
    const validUntil = new Date().getTime() + validForMilliseconds;
    const tokenData = Token.toBinary({
      claims: encodedClaims,
      validUntil: Timestamp.fromDate(new Date(validUntil)),
    });
    const signature = nacl.sign.detached(tokenData, this.privateKey);
    return (
      urlSafeBase64Encode(tokenData) + "." + urlSafeBase64Encode(signature)
    );
  }

  signToBytes(claims: T, validForMilliseconds: number): Uint8Array {
    const encodedClaims = this.codec.toBinary(claims);
    const validUntil = new Date().getTime() + validForMilliseconds;
    const data = Token.toBinary({
      claims: encodedClaims,
      validUntil: Timestamp.fromDate(new Date(validUntil)),
    });
    const signature = nacl.sign.detached(data, this.privateKey);
    return SignedToken.toBinary({ signature, data });
  }
}

function urlSafeBase64Encode(bytes: Uint8Array) {
  const base64 = base64encode(bytes);
  return base64.replace(/\//g, "_").replace(/\+/g, "-").replace(/=+$/, "");
}
