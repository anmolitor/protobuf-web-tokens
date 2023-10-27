use josekit::{
    jws::{
        alg::eddsa::{EddsaJwsAlgorithm::Eddsa, EddsaJwsSigner, EddsaJwsVerifier},
        JwsHeader,
    },
    jwt::JwtPayload,
};
use serde::Serialize;

pub type JwtSigner = (EddsaJwsSigner, EddsaJwsVerifier);

pub fn jwt_encode<T: Serialize>(signer: &JwtSigner, claims: T, expiry_time: usize) -> String {
    let header = JwsHeader::new();
    let value = serde_json::to_value(claims).unwrap();
    let mut map_with_exp = value.as_object().unwrap().clone();
    map_with_exp.insert(
        "exp".to_string(),
        serde_json::Value::from(unix_timestamp() + expiry_time),
    );
    let payload = JwtPayload::from_map(map_with_exp).unwrap();
    josekit::jwt::encode_with_signer(&payload, &header, &signer.0).unwrap()
}

fn unix_timestamp() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

pub fn init_jwt_signer() -> JwtSigner {
    let pem = std::fs::read("private.pem").unwrap();
    let signer = Eddsa.signer_from_pem(&pem).unwrap();
    let key_pair = Eddsa.key_pair_from_pem(&pem).unwrap();
    let jwk = key_pair.to_jwk_public_key();
    let verifier = Eddsa.verifier_from_jwk(&jwk).unwrap();
    (signer, verifier)
}
