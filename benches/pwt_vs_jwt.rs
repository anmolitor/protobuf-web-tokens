use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use prost::Message;
use protobuf_web_token::{self, Signer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[path = "../src/jwt.rs"]
mod jwt;

fn pwt_round_trip<T: Message + Default>(signer: &Signer, value: T) {
    let token = signer.sign(value, Duration::from_secs(100));
    signer.verify::<T>(&token).unwrap();
}

fn jwt_round_trip<T: Serialize + DeserializeOwned>(signer: &jwt::JwtSigner, claims: T) {
    let token: String = jwt::jwt_encode(signer, claims, 100);
    jwt_decode::<T>(signer, &token);
}

#[cfg(test)]
fn criterion_benchmark(c: &mut Criterion) {
    let signer = init_pwt_signer();
    let jwt_signer = jwt::init_jwt_signer();
    let mut small_data_group = c.benchmark_group("small data");
    small_data_group.bench_function("pwt_round_trip", |b| {
        b.iter(|| {
            pwt_round_trip(
                &signer,
                black_box(proto::Simple {
                    some_claim: "test".to_string(),
                }),
            )
        })
    });
    small_data_group.bench_function("jwt_round_trip", |b| {
        b.iter(|| {
            jwt_round_trip(
                &jwt_signer,
                black_box(Simple {
                    some_claim: "test".to_string(),
                }),
            )
        })
    });
    drop(small_data_group);

    let mut complex_data_group = c.benchmark_group("complex_data");
    complex_data_group.bench_function("pwt_round_trip", |b| {
        b.iter(|| {
            pwt_round_trip(
                &signer,
                black_box(proto::Complex {
                    email: "tiberius.estor@andrena.de".to_string(),
                    user_name: "Tiberius".to_string(),
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
                }),
            )
        })
    });
}

mod proto {
    include!(concat!(env!("OUT_DIR"), "/test.rs"));
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Simple {
    some_claim: String,
}

fn init_pwt_signer() -> Signer {
    use protobuf_web_token::ed25519::pkcs8::DecodePrivateKey;
    let pem = std::fs::read("private.pem").unwrap();
    let pem = String::from_utf8(pem).unwrap();
    let key = protobuf_web_token::ed25519::SigningKey::from_pkcs8_pem(&pem).unwrap();
    Signer::new(key)
}

pub fn jwt_decode<T: DeserializeOwned>(signer: &jwt::JwtSigner, token: &str) {
    let (payload, _header) = josekit::jwt::decode_with_verifier(token, &signer.1).unwrap();
    serde_json::from_value::<T>(josekit::Value::Object(payload.into()))
        .map_err(|err| josekit::JoseError::InvalidJson(err.into()))
        .unwrap();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
