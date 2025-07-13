export interface TokenData<T> {
  claims: T;
  validUntil?: Date;
}

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}
