mod envelope;
mod kdf;

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use envelope::{unwrap_key as unwrap_key_inner, wrap_key as wrap_key_inner};
use kdf::{
    KDF_SALT_LENGTH, KEY_LENGTH, derive_master_key_encryption_key as derive_mkek_inner,
    derive_master_password_key as derive_mpk_inner,
    derive_recovery_key_encryption_key as derive_recovery_kek_inner,
};

const SECRET_LENGTH: usize = KEY_LENGTH;

fn generate_random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)?;

    Ok(bytes)
}

fn generate_secret_bytes() -> Result<[u8; SECRET_LENGTH], getrandom::Error> {
    generate_random_bytes()
}

fn secret_array_for_js(mut secret: [u8; SECRET_LENGTH]) -> Box<[u8]> {
    let result = secret.to_vec().into_boxed_slice();
    secret.zeroize();

    result
}

fn crypto_error(message: &'static str) -> JsError {
    JsError::new(message)
}

#[wasm_bindgen]
pub fn generate_account_secret() -> Result<Box<[u8]>, JsError> {
    generate_secret_bytes()
        .map(secret_array_for_js)
        .map_err(|_| crypto_error("Secure random generation failed"))
}

#[wasm_bindgen]
pub fn generate_root_key() -> Result<Box<[u8]>, JsError> {
    generate_secret_bytes()
        .map(secret_array_for_js)
        .map_err(|_| crypto_error("Secure random generation failed"))
}

#[wasm_bindgen]
pub fn generate_vault_key() -> Result<Box<[u8]>, JsError> {
    generate_secret_bytes()
        .map(secret_array_for_js)
        .map_err(|_| crypto_error("Secure random generation failed"))
}

#[wasm_bindgen]
pub fn generate_recovery_key() -> Result<Box<[u8]>, JsError> {
    generate_secret_bytes()
        .map(secret_array_for_js)
        .map_err(|_| crypto_error("Secure random generation failed"))
}

#[wasm_bindgen]
pub fn generate_kdf_salt() -> Result<Box<[u8]>, JsError> {
    generate_random_bytes::<KDF_SALT_LENGTH>()
        .map(|salt| salt.to_vec().into_boxed_slice())
        .map_err(|_| crypto_error("Secure random generation failed"))
}

#[wasm_bindgen]
pub fn derive_master_password_key(
    master_password: &str,
    account_secret: &[u8],
    salt: &[u8],
) -> Result<Box<[u8]>, JsError> {
    let mut key = derive_mpk_inner(master_password, account_secret, salt).map_err(crypto_error)?;

    let result = key.to_vec().into_boxed_slice();
    key.zeroize();

    Ok(result)
}

#[wasm_bindgen]
pub fn derive_master_key_encryption_key(master_password_key: &[u8]) -> Result<Box<[u8]>, JsError> {
    let mut key = derive_mkek_inner(master_password_key).map_err(crypto_error)?;

    let result = key.to_vec().into_boxed_slice();
    key.zeroize();

    Ok(result)
}

#[wasm_bindgen]
pub fn derive_recovery_key_encryption_key(recovery_key: &[u8]) -> Result<Box<[u8]>, JsError> {
    let mut key = derive_recovery_kek_inner(recovery_key).map_err(crypto_error)?;

    let result = key.to_vec().into_boxed_slice();
    key.zeroize();

    Ok(result)
}

#[wasm_bindgen]
pub fn wrap_key(
    key_encryption_key: &[u8],
    key_to_wrap: &[u8],
    aad: &[u8],
) -> Result<Box<[u8]>, JsError> {
    wrap_key_inner(key_encryption_key, key_to_wrap, aad)
        .map(|envelope| envelope.into_boxed_slice())
        .map_err(crypto_error)
}

#[wasm_bindgen]
pub fn unwrap_key(
    key_encryption_key: &[u8],
    envelope: &[u8],
    aad: &[u8],
) -> Result<Box<[u8]>, JsError> {
    unwrap_key_inner(key_encryption_key, envelope, aad)
        .map(|key| key.into_boxed_slice())
        .map_err(crypto_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_256_bit_secret() {
        let secret = generate_secret_bytes().expect("secure randomness should be available");

        assert_eq!(secret.len(), SECRET_LENGTH);
    }

    #[test]
    fn generates_distinct_secrets() {
        let first = generate_secret_bytes().expect("secure randomness should be available");

        let second = generate_secret_bytes().expect("secure randomness should be available");

        assert_ne!(first, second);
    }
}
