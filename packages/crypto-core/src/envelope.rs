use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroize;

use crate::kdf::KEY_LENGTH;

const ENVELOPE_VERSION: u8 = 1;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

const ENVELOPE_HEADER_LENGTH: usize = 1 + NONCE_LENGTH;
const MIN_ENVELOPE_LENGTH: usize = ENVELOPE_HEADER_LENGTH + TAG_LENGTH;

pub fn wrap_key(
    key_encryption_key: &[u8],
    key_to_wrap: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if key_encryption_key.len() != KEY_LENGTH {
        return Err("Key encryption key must be exactly 32 bytes");
    }

    if key_to_wrap.len() != KEY_LENGTH {
        return Err("Wrapped key must be exactly 32 bytes");
    }

    let cipher =
        Aes256Gcm::new_from_slice(key_encryption_key).map_err(|_| "Invalid AES-256-GCM key")?;

    let mut nonce_bytes = [0_u8; NONCE_LENGTH];

    getrandom::fill(&mut nonce_bytes).map_err(|_| "Secure nonce generation failed")?;

    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key_to_wrap,
                aad,
            },
        )
        .map_err(|_| "Key encryption failed")?;

    let mut envelope = Vec::with_capacity(ENVELOPE_HEADER_LENGTH + ciphertext.len());

    envelope.push(ENVELOPE_VERSION);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

pub fn unwrap_key(
    key_encryption_key: &[u8],
    envelope: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if key_encryption_key.len() != KEY_LENGTH {
        return Err("Key encryption key must be exactly 32 bytes");
    }

    if envelope.len() < MIN_ENVELOPE_LENGTH {
        return Err("Invalid key envelope");
    }

    if envelope[0] != ENVELOPE_VERSION {
        return Err("Unsupported key envelope version");
    }

    let nonce_bytes: [u8; NONCE_LENGTH] = envelope[1..ENVELOPE_HEADER_LENGTH]
        .try_into()
        .map_err(|_| "Invalid key envelope nonce")?;

    let nonce = Nonce::from(nonce_bytes);

    let cipher =
        Aes256Gcm::new_from_slice(key_encryption_key).map_err(|_| "Invalid AES-256-GCM key")?;

    let mut plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &envelope[ENVELOPE_HEADER_LENGTH..],
                aad,
            },
        )
        .map_err(|_| "Key envelope authentication failed")?;

    if plaintext.len() != KEY_LENGTH {
        plaintext.zeroize();
        return Err("Invalid unwrapped key length");
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_unwraps_key() {
        let kek = [0x11_u8; KEY_LENGTH];
        let key = [0x22_u8; KEY_LENGTH];
        let aad = b"pm/v1/root-key/test-user";

        let envelope = wrap_key(&kek, &key, aad).expect("wrapping should succeed");

        assert_eq!(envelope[0], ENVELOPE_VERSION);
        assert_eq!(envelope.len(), 1 + NONCE_LENGTH + KEY_LENGTH + TAG_LENGTH);

        let plaintext = unwrap_key(&kek, &envelope, aad).expect("unwrapping should succeed");

        assert_eq!(plaintext, key);
    }

    #[test]
    fn same_key_produces_different_envelopes() {
        let kek = [0x11_u8; KEY_LENGTH];
        let key = [0x22_u8; KEY_LENGTH];
        let aad = b"pm/v1/root-key/test-user";

        let first = wrap_key(&kek, &key, aad).expect("wrapping should succeed");

        let second = wrap_key(&kek, &key, aad).expect("wrapping should succeed");

        assert_ne!(first, second);
    }

    #[test]
    fn rejects_incorrect_aad() {
        let kek = [0x11_u8; KEY_LENGTH];
        let key = [0x22_u8; KEY_LENGTH];

        let envelope = wrap_key(&kek, &key, b"correct-context").expect("wrapping should succeed");

        let result = unwrap_key(&kek, &envelope, b"wrong-context");

        assert!(result.is_err());
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let kek = [0x11_u8; KEY_LENGTH];
        let key = [0x22_u8; KEY_LENGTH];
        let aad = b"pm/v1/root-key/test-user";

        let mut envelope = wrap_key(&kek, &key, aad).expect("wrapping should succeed");

        let last = envelope
            .last_mut()
            .expect("envelope should contain ciphertext");

        *last ^= 0x01;

        let result = unwrap_key(&kek, &envelope, aad);

        assert!(result.is_err());
    }
}
