use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

pub const KEY_LENGTH: usize = 32;
pub const KDF_SALT_LENGTH: usize = 16;

pub const KDF_PROFILE_VERSION: u32 = 1;

pub const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
pub const ARGON2_ITERATIONS: u32 = 2;
pub const ARGON2_PARALLELISM: u32 = 1;

const MKEK_INFO: &[u8] = b"pm/v1/master-key-encryption-key";
const RECOVERY_KEK_INFO: &[u8] = b"pm/v1/recovery-key-encryption-key";

pub fn derive_master_password_key(
    master_password: &str,
    account_secret: &[u8],
    salt: &[u8],
) -> Result<[u8; KEY_LENGTH], &'static str> {
    if account_secret.len() != KEY_LENGTH {
        return Err("Account Secret must be exactly 32 bytes");
    }

    if salt.len() != KDF_SALT_LENGTH {
        return Err("KDF salt must be exactly 16 bytes");
    }

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LENGTH),
    )
    .map_err(|_| "Invalid Argon2 parameters")?;

    let argon2 =
        Argon2::new_with_secret(account_secret, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|_| "Could not initialize Argon2")?;

    let mut output = [0_u8; KEY_LENGTH];

    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut output)
        .map_err(|_| "Argon2 key derivation failed")?;

    Ok(output)
}

fn derive_hkdf_key(
    input_key_material: &[u8],
    info: &[u8],
) -> Result<[u8; KEY_LENGTH], &'static str> {
    if input_key_material.len() != KEY_LENGTH {
        return Err("Input key material must be exactly 32 bytes");
    }

    let hkdf = Hkdf::<Sha256>::new(None, input_key_material);
    let mut output = [0_u8; KEY_LENGTH];

    hkdf.expand(info, &mut output)
        .map_err(|_| "HKDF expansion failed")?;

    Ok(output)
}

pub fn derive_master_key_encryption_key(
    master_password_key: &[u8],
) -> Result<[u8; KEY_LENGTH], &'static str> {
    derive_hkdf_key(master_password_key, MKEK_INFO)
}

pub fn derive_recovery_key_encryption_key(
    recovery_key: &[u8],
) -> Result<[u8; KEY_LENGTH], &'static str> {
    derive_hkdf_key(recovery_key, RECOVERY_KEK_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_password_key_is_deterministic() {
        let account_secret = [0x11_u8; KEY_LENGTH];
        let salt = [0x22_u8; KDF_SALT_LENGTH];

        let first =
            derive_master_password_key("correct horse battery staple", &account_secret, &salt)
                .expect("derivation should succeed");

        let second =
            derive_master_password_key("correct horse battery staple", &account_secret, &salt)
                .expect("derivation should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn account_secret_changes_master_password_key() {
        let first_secret = [0x11_u8; KEY_LENGTH];
        let second_secret = [0x12_u8; KEY_LENGTH];
        let salt = [0x22_u8; KDF_SALT_LENGTH];

        let first = derive_master_password_key("master password", &first_secret, &salt)
            .expect("derivation should succeed");

        let second = derive_master_password_key("master password", &second_secret, &salt)
            .expect("derivation should succeed");

        assert_ne!(first, second);
    }

    #[test]
    fn hkdf_domains_produce_different_keys() {
        let input = [0x33_u8; KEY_LENGTH];

        let mkek = derive_master_key_encryption_key(&input).expect("derivation should succeed");

        let recovery_kek =
            derive_recovery_key_encryption_key(&input).expect("derivation should succeed");

        assert_ne!(mkek, recovery_kek);
    }
}
