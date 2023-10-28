use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use prost::Message;

use base64::{engine::general_purpose, Engine as _};

#[cfg(test)]
mod jwt;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/pwt.rs"));
}
pub extern crate ed25519_dalek as ed25519;

#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Verifier {
    key: VerifyingKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenData<CLAIMS> {
    pub valid_until: SystemTime,
    pub claims: CLAIMS,
}

struct Base64Claims<'a>(&'a str);

struct Base64Signature<'a>(&'a str);

struct BytesClaims(Vec<u8>);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidFormat,
    InvalidBase64,
    InvalidSignature,
    SignatureMismatch,
    ProtobufDecodeError,
    MissingValidUntil,
    TokenExpired,
}

impl Signer {
    pub fn new(key: SigningKey) -> Self {
        Signer { key }
    }

    pub fn as_verifier(&self) -> Verifier {
        Verifier {
            key: self.key.verifying_key(),
        }
    }

    pub fn sign<T: Message>(&self, data: T, valid_for: Duration) -> String {
        let proto_token = self.create_proto_token(data, valid_for);
        let (base64, signature) = self.sign_proto_token(proto_token);
        format!("{base64}.{signature}")
    }

    fn create_proto_token<T: Message>(&self, data: T, valid_for: Duration) -> proto::Token {
        let bytes = data.encode_to_vec();
        proto::Token {
            valid_until: Some((SystemTime::now() + valid_for).into()),
            claims: bytes,
        }
    }

    fn sign_proto_token(&self, proto_token: proto::Token) -> (String, String) {
        let bytes = proto_token.encode_to_vec();
        let signature = self.key.sign(&bytes);
        let base64 = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let signature = general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        (base64, signature)
    }
}

impl Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn verify<CLAIMS: Message + Default>(
        &self,
        token: &str,
    ) -> Result<TokenData<CLAIMS>, Error> {
        let (claims, signature) = parse_token(token)?;
        let bytes = claims.to_bytes()?;
        self.verify_signature(&bytes, &signature)?;

        let token_data = bytes.decode_metadata()?;
        let claims =
            CLAIMS::decode(token_data.claims.as_slice()).map_err(|_| Error::ProtobufDecodeError)?;
        Ok(TokenData {
            valid_until: token_data.valid_until,
            claims,
        })
    }

    pub fn verify_and_check_expiry<CLAIMS: Message + Default>(
        &self,
        token: &str,
    ) -> Result<CLAIMS, Error> {
        let (claims, signature) = parse_token(token)?;
        let bytes = claims.to_bytes()?;
        self.verify_signature(&bytes, &signature)?;

        let token_data = bytes.decode_metadata()?;

        let now = SystemTime::now();
        if now > token_data.valid_until {
            return Result::Err(Error::TokenExpired);
        }

        CLAIMS::decode(token_data.claims.as_slice()).map_err(|_| Error::ProtobufDecodeError)
    }

    fn verify_signature(
        &self,
        bytes: &BytesClaims,
        signature: &Base64Signature,
    ) -> Result<(), Error> {
        let signature = general_purpose::URL_SAFE_NO_PAD
            .decode(signature.0)
            .map_err(|_| Error::InvalidBase64)?;
        let signature =
            Signature::from_slice(signature.as_slice()).map_err(|_| Error::InvalidSignature)?;

        self.key
            .verify(&bytes.0, &signature)
            .map_err(|_| Error::SignatureMismatch)?;
        Ok(())
    }
}

impl<'a> Base64Claims<'a> {
    pub fn to_bytes(&'a self) -> Result<BytesClaims, Error> {
        general_purpose::URL_SAFE_NO_PAD
            .decode(self.0)
            .map(BytesClaims)
            .map_err(|_| Error::InvalidBase64)
    }
}

impl BytesClaims {
    pub fn decode_metadata(&self) -> Result<TokenData<Vec<u8>>, Error> {
        let token =
            proto::Token::decode(self.0.as_slice()).map_err(|_| Error::ProtobufDecodeError)?;
        let valid_until: SystemTime = token
            .valid_until
            .ok_or(Error::MissingValidUntil)?
            .try_into()
            .map_err(|_| Error::MissingValidUntil)?;
        Ok(TokenData {
            valid_until,
            claims: token.claims,
        })
    }
}

fn parse_token(token: &str) -> Result<(Base64Claims<'_>, Base64Signature<'_>), Error> {
    let (data, signature) = token.split_once('.').ok_or(Error::InvalidFormat)?;
    Ok((Base64Claims(data), Base64Signature(signature)))
}

pub fn decode<CLAIMS: Message + Default>(token: &str) -> Result<TokenData<CLAIMS>, Error> {
    let (data, _signature) = token.split_once('.').ok_or(Error::InvalidFormat)?;
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| Error::InvalidBase64)?;

    let decoded_metadata =
        proto::Token::decode(bytes.as_slice()).map_err(|_| Error::ProtobufDecodeError)?;
    let valid_until = decoded_metadata
        .valid_until
        .ok_or(Error::MissingValidUntil)?
        .try_into()
        .map_err(|_| Error::MissingValidUntil)?;
    let claims = CLAIMS::decode(decoded_metadata.claims.as_slice())
        .map_err(|_| Error::ProtobufDecodeError)?;
    Ok(TokenData {
        valid_until,
        claims,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use ed25519::pkcs8::DecodePrivateKey;
    use serde::Serialize;

    use super::*;
    use crate::jwt;

    mod proto {
        include!(concat!(env!("OUT_DIR"), "/test.rs"));
    }

    #[derive(Debug, Clone, Serialize)]
    struct Simple {
        some_claim: String,
    }

    fn init_signer() -> Signer {
        let pem = std::fs::read("test_resources/private.pem").unwrap();
        let pem = String::from_utf8(pem).unwrap();
        let key = SigningKey::from_pkcs8_pem(&pem).unwrap();
        Signer { key }
    }

    #[test]
    fn happy_case() {
        let pwt_signer = init_signer();
        let simple = proto::Simple {
            some_claim: "test contents".to_string(),
        };
        let pwt = pwt_signer.sign(simple.clone(), Duration::from_secs(5));
        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify_and_check_expiry::<proto::Simple>(&pwt),
            Result::Ok(simple)
        );
    }

    #[test]
    fn signature_is_verified_and_prevents_tampering() {
        let pwt_signer = init_signer();
        let proto_token = pwt_signer.create_proto_token(
            proto::Simple {
                some_claim: "test contents".to_string(),
            },
            Duration::from_secs(5),
        );
        let (_data, signature) = pwt_signer.sign_proto_token(proto_token);
        let other_proto_token = pwt_signer.create_proto_token(
            proto::Simple {
                some_claim: "tampered contents".to_string(),
            },
            Duration::from_secs(5),
        );
        let (other_data, _) = pwt_signer.sign_proto_token(other_proto_token);

        let tampered_token = format!("{other_data}.{signature}");

        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify::<proto::Simple>(&tampered_token),
            Result::Err(Error::SignatureMismatch)
        );
    }

    #[test]
    fn invalid_format() {
        let pwt_signer = init_signer();
        assert_eq!(
            pwt_signer.as_verifier().verify::<()>("invalid"),
            Result::Err(Error::InvalidFormat)
        );
    }

    #[test]
    fn invalid_base64() {
        let pwt_signer = init_signer();
        assert_eq!(
            pwt_signer.as_verifier().verify::<()>("invalid.base64"),
            Result::Err(Error::InvalidBase64)
        );
    }

    #[test]
    fn invalid_signature() {
        let pwt_signer = init_signer();
        let base64 = general_purpose::URL_SAFE_NO_PAD.encode("base64");
        assert_eq!(
            pwt_signer
                .as_verifier()
                .verify::<()>(&format!("{base64}.{base64}")),
            Result::Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn protobuf_decode_mismatch() {
        let pwt_signer = init_signer();
        let pwt = pwt_signer.sign(
            proto::Simple {
                some_claim: "test contents".to_string(),
            },
            Duration::from_secs(5),
        );
        assert_eq!(
            pwt_signer.as_verifier().verify::<proto::Complex>(&pwt),
            Result::Err(Error::ProtobufDecodeError)
        );
    }

    #[test]
    fn size_is_smaller_than_jwt() {
        let jwt_signer = jwt::init_jwt_signer();
        let pwt_signer = init_signer();

        let pwt = pwt_signer.sign(
            proto::Simple {
                some_claim: "test contents".to_string(),
            },
            Duration::from_secs(300),
        );
        println!("{pwt}");
        let jwt = jwt::jwt_encode(
            &jwt_signer,
            Simple {
                some_claim: "test contents".to_string(),
            },
            300,
        );
        let pwt_len = f64::from(u32::try_from(pwt.len()).unwrap());
        let jwt_len = f64::from(u32::try_from(jwt.len()).unwrap());
        assert!(
            pwt_len * 1.2 < jwt_len,
            "{pwt} was not small enough in comparison to {jwt}"
        );
    }

    #[derive(Debug, Clone, Serialize)]
    struct Complex {
        email: String,
        user_name: String,
        user_id: String,
        valid_until: SystemTime,
        roles: Vec<String>,
        nested: Nested,
    }

    #[derive(Debug, Clone, Serialize)]
    struct Nested {
        team_id: String,
        team_name: String,
    }

    #[test]
    fn size_is_smaller_than_jwt_complex() {
        let jwt_signer = jwt::init_jwt_signer();
        let pwt_signer = init_signer();
        let now = SystemTime::now();

        let pwt = pwt_signer.sign(
            proto::Complex {
                email: "andreas.molitor@andrena.de".to_string(),
                user_name: "Andreas Molitor".to_string(),
                user_id: 123456789,
                roles: vec![
                    proto::Role::ReadFeatureFoo.into(),
                    proto::Role::WriteFeatureFoo.into(),
                    proto::Role::ReadFeatureBar.into(),
                ],
                nested: Some(proto::Nested {
                    team_id: 3432535236263,
                    team_name: "andrena".to_string(),
                }),
            },
            Duration::from_secs(300),
        );
        let jwt = jwt::jwt_encode(
            &jwt_signer,
            Complex {
                email: "andreas.molitor@andrena.de".to_string(),
                user_name: "Andreas Molitor".to_string(),
                user_id: "123456789".to_string(),
                valid_until: (now + Duration::from_secs(5)),
                roles: vec![
                    "ReadFeatureFoo".to_string(),
                    "WriteFeatureFoo".to_string(),
                    "ReadFeatureBar".to_string(),
                ],
                nested: Nested {
                    team_id: "3432535236263".to_string(),
                    team_name: "andrena".to_string(),
                },
            },
            300,
        );
        let pwt_len = f64::from(u32::try_from(pwt.len()).unwrap());
        let jwt_len = f64::from(u32::try_from(jwt.len()).unwrap());
        assert!(
            pwt_len * 2.0 < jwt_len,
            "{pwt} was not small enough in comparison to {jwt}"
        );
    }
}
