use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload as AeadPayload},
};

use serde::{Deserialize, Serialize};

use wasm_bindgen::prelude::*;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    envelope::{unwrap_key, wrap_key},
    kdf::KEY_LENGTH,
    unlock::UnlockedVault,
};

const ITEM_PAYLOAD_VERSION: u32 = 1;

const ITEM_CIPHERTEXT_VERSION: u8 = 1;

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

const CIPHERTEXT_HEADER_LENGTH: usize = 1 + NONCE_LENGTH;

const MIN_CIPHERTEXT_LENGTH: usize = CIPHERTEXT_HEADER_LENGTH + TAG_LENGTH;

const MAX_NAME_BYTES: usize = 512;
const MAX_USERNAME_BYTES: usize = 2048;
const MAX_PASSWORD_BYTES: usize = 16 * 1024;

const MAX_URLS: usize = 32;
const MAX_URL_BYTES: usize = 4096;

const MAX_NOTES_BYTES: usize = 64 * 1024;

const MAX_SERIALIZED_PAYLOAD_BYTES: usize = 96 * 1024;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginItemInput {
    name: String,
    username: String,
    password: String,
    urls: Vec<String>,
    notes: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, Debug, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginItemPayload {
    schema_version: u32,

    item_type: String,

    name: String,
    username: String,
    password: String,

    urls: Vec<String>,

    notes: String,
}

impl LoginItemInput {
    fn validate(&self) -> Result<(), &'static str> {
        if self.name.is_empty() || self.name.len() > MAX_NAME_BYTES {
            return Err("Invalid item name");
        }

        if self.username.len() > MAX_USERNAME_BYTES {
            return Err("Invalid username");
        }

        if self.password.len() > MAX_PASSWORD_BYTES {
            return Err("Invalid password");
        }

        if self.urls.len() > MAX_URLS {
            return Err("Too many URLs");
        }

        if self.urls.iter().any(|url| url.len() > MAX_URL_BYTES) {
            return Err("Invalid URL");
        }

        if self.notes.len() > MAX_NOTES_BYTES {
            return Err("Notes are too large");
        }

        Ok(())
    }
}

impl From<LoginItemInput> for LoginItemPayload {
    fn from(mut input: LoginItemInput) -> Self {
        Self {
            schema_version: ITEM_PAYLOAD_VERSION,
            item_type: "LOGIN".to_owned(),

            name: std::mem::take(&mut input.name),
            username: std::mem::take(&mut input.username),
            password: std::mem::take(&mut input.password),
            urls: std::mem::take(&mut input.urls),
            notes: std::mem::take(&mut input.notes),
        }
    }
}

#[wasm_bindgen]
pub struct EncryptedItemRevision {
    item_key_envelope: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedItemRevision {
    #[wasm_bindgen(getter)]
    pub fn payload_version(&self) -> u32 {
        ITEM_PAYLOAD_VERSION
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext_version(&self) -> u32 {
        ITEM_CIPHERTEXT_VERSION as u32
    }

    pub fn item_key_envelope(&self) -> Box<[u8]> {
        self.item_key_envelope.clone().into_boxed_slice()
    }

    pub fn ciphertext(&self) -> Box<[u8]> {
        self.ciphertext.clone().into_boxed_slice()
    }

    pub fn clear(&mut self) {
        self.item_key_envelope.zeroize();
        self.ciphertext.zeroize();
    }
}

impl Drop for EncryptedItemRevision {
    fn drop(&mut self) {
        self.clear();
    }
}

fn encrypt_payload(item_key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
    if item_key.len() != KEY_LENGTH {
        return Err("Invalid item key");
    }

    if aad.is_empty() {
        return Err("Item payload AAD must not be empty");
    }

    let cipher = Aes256Gcm::new_from_slice(item_key).map_err(|_| "Invalid item key")?;

    let mut nonce_bytes = [0_u8; NONCE_LENGTH];

    getrandom::fill(&mut nonce_bytes).map_err(|_| "Secure nonce generation failed")?;

    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            AeadPayload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "Item encryption failed")?;

    let mut result = Vec::with_capacity(CIPHERTEXT_HEADER_LENGTH + ciphertext.len());

    result.push(ITEM_CIPHERTEXT_VERSION);

    result.extend_from_slice(&nonce_bytes);

    result.extend_from_slice(&ciphertext);

    Ok(result)
}

fn decrypt_payload(
    item_key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if item_key.len() != KEY_LENGTH {
        return Err("Item decryption failed");
    }

    if aad.is_empty() || ciphertext.len() < MIN_CIPHERTEXT_LENGTH {
        return Err("Item decryption failed");
    }

    if ciphertext[0] != ITEM_CIPHERTEXT_VERSION {
        return Err("Item decryption failed");
    }

    let nonce_bytes: [u8; NONCE_LENGTH] = ciphertext[1..CIPHERTEXT_HEADER_LENGTH]
        .try_into()
        .map_err(|_| "Item decryption failed")?;

    let nonce = Nonce::from(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(item_key).map_err(|_| "Item decryption failed")?;

    cipher
        .decrypt(
            &nonce,
            AeadPayload {
                msg: &ciphertext[CIPHERTEXT_HEADER_LENGTH..],
                aad,
            },
        )
        .map_err(|_| "Item decryption failed")
}

fn encrypt_login_item_inner(
    vault_key: &[u8],
    input: LoginItemInput,
    item_key_aad: &[u8],
    payload_aad: &[u8],
) -> Result<EncryptedItemRevision, &'static str> {
    if item_key_aad.is_empty() || payload_aad.is_empty() {
        return Err("Item AAD must not be empty");
    }

    input.validate()?;

    let payload = LoginItemPayload::from(input);

    let serialized =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| "Item serialization failed")?);

    if serialized.len() > MAX_SERIALIZED_PAYLOAD_BYTES {
        return Err("Item payload is too large");
    }

    let mut item_key = [0_u8; KEY_LENGTH];

    getrandom::fill(&mut item_key).map_err(|_| "Secure random generation failed")?;

    let item_key = Zeroizing::new(item_key);

    let item_key_envelope = wrap_key(vault_key, item_key.as_ref(), item_key_aad)?;

    let ciphertext = encrypt_payload(item_key.as_ref(), serialized.as_ref(), payload_aad)?;

    Ok(EncryptedItemRevision {
        item_key_envelope,
        ciphertext,
    })
}

fn decrypt_login_item_inner(
    vault_key: &[u8],
    item_key_envelope: &[u8],
    item_key_aad: &[u8],
    ciphertext: &[u8],
    payload_aad: &[u8],
) -> Result<LoginItemPayload, &'static str> {
    let item_key = Zeroizing::new(
        unwrap_key(vault_key, item_key_envelope, item_key_aad)
            .map_err(|_| "Item decryption failed")?,
    );

    let plaintext = Zeroizing::new(decrypt_payload(item_key.as_ref(), ciphertext, payload_aad)?);

    if plaintext.len() > MAX_SERIALIZED_PAYLOAD_BYTES {
        return Err("Item decryption failed");
    }

    let payload: LoginItemPayload =
        serde_json::from_slice(plaintext.as_ref()).map_err(|_| "Item decryption failed")?;

    if payload.schema_version != ITEM_PAYLOAD_VERSION || payload.item_type != "LOGIN" {
        return Err("Unsupported item payload");
    }

    Ok(payload)
}

#[wasm_bindgen]
pub fn encrypt_login_item(
    vault: &UnlockedVault,
    input: JsValue,
    item_key_aad: &[u8],
    payload_aad: &[u8],
) -> Result<EncryptedItemRevision, JsError> {
    let input: LoginItemInput =
        serde_wasm_bindgen::from_value(input).map_err(|_| JsError::new("Invalid login item"))?;

    let vault_key = vault.vault_key_bytes().map_err(JsError::new)?;

    encrypt_login_item_inner(vault_key, input, item_key_aad, payload_aad).map_err(JsError::new)
}

#[wasm_bindgen]
pub fn decrypt_login_item(
    vault: &UnlockedVault,
    item_key_envelope: &[u8],
    item_key_aad: &[u8],
    ciphertext: &[u8],
    payload_aad: &[u8],
) -> Result<JsValue, JsError> {
    let vault_key = vault.vault_key_bytes().map_err(JsError::new)?;

    let payload = decrypt_login_item_inner(
        vault_key,
        item_key_envelope,
        item_key_aad,
        ciphertext,
        payload_aad,
    )
    .map_err(JsError::new)?;

    serde_wasm_bindgen::to_value(&payload).map_err(|_| JsError::new("Item serialization failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEM_KEY_AAD: &[u8] =
        b"pm:v1:item-key:vault:test-vault:item:test-item:revision:1:vault-key-version:1";

    const PAYLOAD_AAD: &[u8] =
        b"pm:v1:item-payload:vault:test-vault:item:test-item:revision:1:item-key-version:1";

    fn login_input() -> LoginItemInput {
        LoginItemInput {
            name: "GitHub".to_owned(),

            username: "daniel@example.com".to_owned(),

            password: "super-secret-password".to_owned(),

            urls: vec!["https://github.com".to_owned()],

            notes: "Personal account".to_owned(),
        }
    }

    #[test]
    fn encrypts_and_decrypts_login_item() {
        let vault_key = [0x11_u8; KEY_LENGTH];

        let encrypted =
            encrypt_login_item_inner(&vault_key, login_input(), ITEM_KEY_AAD, PAYLOAD_AAD)
                .expect("encryption should succeed");

        let decrypted = decrypt_login_item_inner(
            &vault_key,
            &encrypted.item_key_envelope,
            ITEM_KEY_AAD,
            &encrypted.ciphertext,
            PAYLOAD_AAD,
        )
        .expect("decryption should succeed");

        assert_eq!(decrypted.schema_version, 1,);

        assert_eq!(decrypted.item_type, "LOGIN",);

        assert_eq!(decrypted.name, "GitHub",);

        assert_eq!(decrypted.username, "daniel@example.com",);

        assert_eq!(decrypted.password, "super-secret-password",);

        assert_eq!(decrypted.urls, vec!["https://github.com".to_owned(),],);

        assert_eq!(decrypted.notes, "Personal account",);
    }

    #[test]
    fn same_item_produces_fresh_crypto_material() {
        let vault_key = [0x11_u8; KEY_LENGTH];

        let first = encrypt_login_item_inner(&vault_key, login_input(), ITEM_KEY_AAD, PAYLOAD_AAD)
            .expect("encryption should succeed");

        let second = encrypt_login_item_inner(&vault_key, login_input(), ITEM_KEY_AAD, PAYLOAD_AAD)
            .expect("encryption should succeed");

        assert_ne!(first.item_key_envelope, second.item_key_envelope,);

        assert_ne!(first.ciphertext, second.ciphertext,);
    }

    #[test]
    fn wrong_item_key_aad_is_rejected() {
        let vault_key = [0x11_u8; KEY_LENGTH];

        let encrypted =
            encrypt_login_item_inner(&vault_key, login_input(), ITEM_KEY_AAD, PAYLOAD_AAD)
                .expect("encryption should succeed");

        let result = decrypt_login_item_inner(
            &vault_key,
            &encrypted.item_key_envelope,
            b"wrong-item-key-context",
            &encrypted.ciphertext,
            PAYLOAD_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_payload_aad_is_rejected() {
        let vault_key = [0x11_u8; KEY_LENGTH];

        let encrypted =
            encrypt_login_item_inner(&vault_key, login_input(), ITEM_KEY_AAD, PAYLOAD_AAD)
                .expect("encryption should succeed");

        let result = decrypt_login_item_inner(
            &vault_key,
            &encrypted.item_key_envelope,
            ITEM_KEY_AAD,
            &encrypted.ciphertext,
            b"wrong-payload-context",
        );

        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let vault_key = [0x11_u8; KEY_LENGTH];

        let mut encrypted =
            encrypt_login_item_inner(&vault_key, login_input(), ITEM_KEY_AAD, PAYLOAD_AAD)
                .expect("encryption should succeed");

        let last = encrypted
            .ciphertext
            .last_mut()
            .expect("ciphertext should not be empty");

        *last ^= 0x01;

        let result = decrypt_login_item_inner(
            &vault_key,
            &encrypted.item_key_envelope,
            ITEM_KEY_AAD,
            &encrypted.ciphertext,
            PAYLOAD_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_vault_key_is_rejected() {
        let vault_key = [0x11_u8; KEY_LENGTH];

        let encrypted =
            encrypt_login_item_inner(&vault_key, login_input(), ITEM_KEY_AAD, PAYLOAD_AAD)
                .expect("encryption should succeed");

        let wrong_vault_key = [0x22_u8; KEY_LENGTH];

        let result = decrypt_login_item_inner(
            &wrong_vault_key,
            &encrypted.item_key_envelope,
            ITEM_KEY_AAD,
            &encrypted.ciphertext,
            PAYLOAD_AAD,
        );

        assert!(result.is_err());
    }
}
