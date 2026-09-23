use wasm_bindgen::prelude::*;

const SECRET_LENGTH: usize = 32;

fn generate_secret_bytes() -> Result<[u8; SECRET_LENGTH], getrandom::Error> {
    let mut secret = [0_u8; SECRET_LENGTH];
    getrandom::fill(&mut secret)?;

    Ok(secret)
}

fn generate_secret_for_js() -> Result<Box<[u8]>, JsError> {
    generate_secret_bytes()
        .map(|secret| secret.to_vec().into_boxed_slice())
        .map_err(|_| JsError::new("Secure random generation failed"))
}

#[wasm_bindgen]
pub fn generate_account_secret() -> Result<Box<[u8]>, JsError> {
    generate_secret_for_js()
}

#[wasm_bindgen]
pub fn generate_root_key() -> Result<Box<[u8]>, JsError> {
    generate_secret_for_js()
}

#[wasm_bindgen]
pub fn generate_vault_key() -> Result<Box<[u8]>, JsError> {
    generate_secret_for_js()
}

#[wasm_bindgen]
pub fn generate_recovery_key() -> Result<Box<[u8]>, JsError> {
    generate_secret_for_js()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_256_bit_secret() {
        let secret = generate_secret_bytes().expect("secure randomness should be available");

        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn generates_distinct_secrets() {
        let first = generate_secret_bytes().expect("secure randomness should be available");
        let second = generate_secret_bytes().expect("secure randomness should be available");

        assert_ne!(first, second);
    }
}
