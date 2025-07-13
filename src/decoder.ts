import { base64decode,  IMessageType } from "@protobuf-ts/runtime";
import { Token } from "./pwt.js";
import { Timestamp } from "./google/protobuf/timestamp.js";
import { TokenData } from "./types.js";

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
    if (!tokenData.validUntil) {
      throw new Error("Token did not include expiry date");
    }
    const validUntil =
      tokenData.validUntil && Timestamp.toDate(tokenData.validUntil);

    return { claims, validUntil };
  }
}
