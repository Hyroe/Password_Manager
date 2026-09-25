use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    envelope::unwrap_key,
    kdf::{
        KDF_SALT_LENGTH, KEY_LENGTH, derive_master_key_encryption_key, derive_master_password_key,
    },
};

#[wasm_bindgen]
pub struct UnlockedVault {
    root_key: [u8; KEY_LENGTH],
    vault_key: [u8; KEY_LENGTH],
    cleared: bool,
}

#[wasm_bindgen]
impl UnlockedVault {
    #[wasm_bindgen(getter)]
    pub fn is_cleared(&self) -> bool {
        self.cleared
    }

    pub fn clear(&mut self) {
        self.root_key.zeroize();
        self.vault_key.zeroize();
        self.cleared = true;
    }
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        self.clear();
    }
}

pub fn unlock_personal_vault_inner(
    master_password: &str,
    account_secret: &[u8],
    kdf_salt: &[u8],
    root_key_envelope: &[u8],
    root_key_aad: &[u8],
    vault_key_envelope: &[u8],
    vault_key_aad: &[u8],
) -> Result<UnlockedVault, &'static str> {
    if master_password.is_empty() {
        return Err("Master Password must not be empty");
    }

    if account_secret.len() != KEY_LENGTH {
        return Err("Account Secret must be exactly 32 bytes");
    }

    if kdf_salt.len() != KDF_SALT_LENGTH {
        return Err("KDF salt must be exactly 16 bytes");
    }

    if root_key_aad.is_empty() || vault_key_aad.is_empty() {
        return Err("Key envelope AAD must not be empty");
    }

    let master_password_key = Zeroizing::new(derive_master_password_key(
        master_password,
        account_secret,
        kdf_salt,
    )?);

    let master_key_encryption_key = Zeroizing::new(derive_master_key_encryption_key(
        master_password_key.as_ref(),
    )?);

    let root_key_plaintext = Zeroizing::new(unwrap_key(
        master_key_encryption_key.as_ref(),
        root_key_envelope,
        root_key_aad,
    )?);

    if root_key_plaintext.len() != KEY_LENGTH {
        return Err("Invalid root key length");
    }

    let mut root_key = [0_u8; KEY_LENGTH];

    root_key.copy_from_slice(root_key_plaintext.as_slice());

    let vault_key_plaintext = match unwrap_key(&root_key, vault_key_envelope, vault_key_aad) {
        Ok(key) => Zeroizing::new(key),

        Err(error) => {
            root_key.zeroize();
            return Err(error);
        }
    };

    if vault_key_plaintext.len() != KEY_LENGTH {
        root_key.zeroize();
        return Err("Invalid vault key length");
    }

    let mut vault_key = [0_u8; KEY_LENGTH];

    vault_key.copy_from_slice(vault_key_plaintext.as_slice());

    Ok(UnlockedVault {
        root_key,
        vault_key,
        cleared: false,
    })
}

#[wasm_bindgen]
pub fn unlock_personal_vault(
    master_password: &str,
    account_secret: &[u8],
    kdf_salt: &[u8],
    root_key_envelope: &[u8],
    root_key_aad: &[u8],
    vault_key_envelope: &[u8],
    vault_key_aad: &[u8],
) -> Result<UnlockedVault, JsError> {
    unlock_personal_vault_inner(
        master_password,
        account_secret,
        kdf_salt,
        root_key_envelope,
        root_key_aad,
        vault_key_envelope,
        vault_key_aad,
    )
    .map_err(JsError::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bootstrap::create_account_bootstrap_inner;

    const ROOT_AAD: &[u8] = b"pm:v1:ark:crypto-profile:test-profile:key-version:1";

    const RECOVERY_AAD: &[u8] = b"pm:v1:recovery-ark:crypto-profile:test-profile:key-version:1";

    const VAULT_AAD: &[u8] = b"pm:v1:pvk:vault:test-vault:key-version:1";

    #[test]
    fn unlocks_vault_with_correct_credentials() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();
        let kdf_salt = bootstrap.kdf_salt();
        let root_envelope = bootstrap.root_key_envelope();
        let vault_envelope = bootstrap.vault_key_envelope();

        let unlocked = unlock_personal_vault_inner(
            "correct horse battery staple",
            &account_secret,
            &kdf_salt,
            &root_envelope,
            ROOT_AAD,
            &vault_envelope,
            VAULT_AAD,
        )
        .expect("vault should unlock");

        assert!(!unlocked.cleared);
        assert_eq!(unlocked.root_key.len(), KEY_LENGTH);
        assert_eq!(unlocked.vault_key.len(), KEY_LENGTH);
    }

    #[test]
    fn wrong_master_password_cannot_unlock() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();
        let kdf_salt = bootstrap.kdf_salt();
        let root_envelope = bootstrap.root_key_envelope();
        let vault_envelope = bootstrap.vault_key_envelope();

        let result = unlock_personal_vault_inner(
            "wrong password",
            &account_secret,
            &kdf_salt,
            &root_envelope,
            ROOT_AAD,
            &vault_envelope,
            VAULT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_account_secret_cannot_unlock() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let kdf_salt = bootstrap.kdf_salt();
        let root_envelope = bootstrap.root_key_envelope();
        let vault_envelope = bootstrap.vault_key_envelope();

        let wrong_account_secret = [0x42_u8; KEY_LENGTH];

        let result = unlock_personal_vault_inner(
            "correct horse battery staple",
            &wrong_account_secret,
            &kdf_salt,
            &root_envelope,
            ROOT_AAD,
            &vault_envelope,
            VAULT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_root_aad_cannot_unlock() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();
        let kdf_salt = bootstrap.kdf_salt();
        let root_envelope = bootstrap.root_key_envelope();
        let vault_envelope = bootstrap.vault_key_envelope();

        let result = unlock_personal_vault_inner(
            "correct horse battery staple",
            &account_secret,
            &kdf_salt,
            &root_envelope,
            b"wrong-root-context",
            &vault_envelope,
            VAULT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_vault_aad_cannot_unlock() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();
        let kdf_salt = bootstrap.kdf_salt();
        let root_envelope = bootstrap.root_key_envelope();
        let vault_envelope = bootstrap.vault_key_envelope();

        let result = unlock_personal_vault_inner(
            "correct horse battery staple",
            &account_secret,
            &kdf_salt,
            &root_envelope,
            ROOT_AAD,
            &vault_envelope,
            b"wrong-vault-context",
        );

        assert!(result.is_err());
    }

    #[test]
    fn clear_zeroizes_unlocked_keys() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();
        let kdf_salt = bootstrap.kdf_salt();
        let root_envelope = bootstrap.root_key_envelope();
        let vault_envelope = bootstrap.vault_key_envelope();

        let mut unlocked = unlock_personal_vault_inner(
            "correct horse battery staple",
            &account_secret,
            &kdf_salt,
            &root_envelope,
            ROOT_AAD,
            &vault_envelope,
            VAULT_AAD,
        )
        .expect("vault should unlock");

        unlocked.clear();

        assert!(unlocked.cleared);
        assert_eq!(unlocked.root_key, [0_u8; KEY_LENGTH]);
        assert_eq!(unlocked.vault_key, [0_u8; KEY_LENGTH]);
    }
}
