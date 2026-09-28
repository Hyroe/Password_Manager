use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    envelope::{unwrap_key, wrap_key},
    kdf::{
        ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, KDF_PROFILE_VERSION,
        KDF_SALT_LENGTH, KEY_LENGTH, derive_master_key_encryption_key, derive_master_password_key,
    },
};

const PROTOCOL_VERSION: u32 = 1;

fn generate_kdf_salt() -> Result<[u8; KDF_SALT_LENGTH], &'static str> {
    let mut salt = [0_u8; KDF_SALT_LENGTH];

    getrandom::fill(&mut salt).map_err(|_| "Secure random generation failed")?;

    Ok(salt)
}

#[wasm_bindgen]
pub struct MasterPasswordChangeResult {
    kdf_salt: [u8; KDF_SALT_LENGTH],
    root_key_envelope: Vec<u8>,
}

#[wasm_bindgen]
impl MasterPasswordChangeResult {
    #[wasm_bindgen(getter)]
    pub fn protocol_version(&self) -> u32 {
        PROTOCOL_VERSION
    }

    #[wasm_bindgen(getter)]
    pub fn kdf_profile_version(&self) -> u32 {
        KDF_PROFILE_VERSION
    }

    #[wasm_bindgen(getter)]
    pub fn argon2_memory_kib(&self) -> u32 {
        ARGON2_MEMORY_KIB
    }

    #[wasm_bindgen(getter)]
    pub fn argon2_iterations(&self) -> u32 {
        ARGON2_ITERATIONS
    }

    #[wasm_bindgen(getter)]
    pub fn argon2_parallelism(&self) -> u32 {
        ARGON2_PARALLELISM
    }

    pub fn kdf_salt(&self) -> Box<[u8]> {
        self.kdf_salt.to_vec().into_boxed_slice()
    }

    pub fn root_key_envelope(&self) -> Box<[u8]> {
        self.root_key_envelope.clone().into_boxed_slice()
    }

    pub fn clear(&mut self) {
        self.kdf_salt.zeroize();
        self.root_key_envelope.zeroize();
    }
}

impl Drop for MasterPasswordChangeResult {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) fn change_master_password_inner(
    current_master_password: &str,
    new_master_password: &str,
    account_secret: &[u8],
    current_kdf_salt: &[u8],
    current_root_key_envelope: &[u8],
    root_key_aad: &[u8],
) -> Result<MasterPasswordChangeResult, &'static str> {
    if current_master_password.is_empty() {
        return Err("Current Master Password must not be empty");
    }

    if new_master_password.is_empty() {
        return Err("New Master Password must not be empty");
    }

    if account_secret.len() != KEY_LENGTH {
        return Err("Account Secret must be exactly 32 bytes");
    }

    if current_kdf_salt.len() != KDF_SALT_LENGTH {
        return Err("KDF salt must be exactly 16 bytes");
    }

    if root_key_aad.is_empty() {
        return Err("Root key envelope AAD must not be empty");
    }

    /*
     * Current Master Password + Account Secret
     * + current KDF salt
     *      ↓ Argon2id
     * current MPK
     *      ↓ HKDF
     * current MKEK
     *      ↓ unwrap
     * existing ARK
     *
     * ARK remains inside Rust.
     */
    let current_master_password_key = Zeroizing::new(derive_master_password_key(
        current_master_password,
        account_secret,
        current_kdf_salt,
    )?);

    let current_master_key_encryption_key = Zeroizing::new(derive_master_key_encryption_key(
        current_master_password_key.as_ref(),
    )?);

    let root_key = Zeroizing::new(unwrap_key(
        current_master_key_encryption_key.as_ref(),
        current_root_key_envelope,
        root_key_aad,
    )?);

    if root_key.len() != KEY_LENGTH {
        return Err("Invalid root key length");
    }

    /*
     * Password change always generates a fresh
     * KDF salt.
     *
     * New Master Password + same Account Secret
     * + new salt
     *      ↓ Argon2id
     * new MPK
     *      ↓ HKDF
     * new MKEK
     */
    let kdf_salt = generate_kdf_salt()?;

    let new_master_password_key = Zeroizing::new(derive_master_password_key(
        new_master_password,
        account_secret,
        &kdf_salt,
    )?);

    let new_master_key_encryption_key = Zeroizing::new(derive_master_key_encryption_key(
        new_master_password_key.as_ref(),
    )?);

    /*
     * Re-wrap the SAME ARK.
     *
     * Recovery envelope, PVK and all item keys
     * remain unchanged.
     */
    let root_key_envelope = wrap_key(
        new_master_key_encryption_key.as_ref(),
        root_key.as_slice(),
        root_key_aad,
    )?;

    Ok(MasterPasswordChangeResult {
        kdf_salt,
        root_key_envelope,
    })
}

#[wasm_bindgen]
pub fn change_master_password(
    current_master_password: &str,
    new_master_password: &str,
    account_secret: &[u8],
    current_kdf_salt: &[u8],
    current_root_key_envelope: &[u8],
    root_key_aad: &[u8],
) -> Result<MasterPasswordChangeResult, JsError> {
    change_master_password_inner(
        current_master_password,
        new_master_password,
        account_secret,
        current_kdf_salt,
        current_root_key_envelope,
        root_key_aad,
    )
    .map_err(JsError::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        bootstrap::create_account_bootstrap_inner,
        envelope::unwrap_key,
        kdf::{derive_master_key_encryption_key, derive_master_password_key},
        unlock::unlock_personal_vault_inner,
    };

    const OLD_MASTER_PASSWORD: &str = "correct horse battery staple";

    const NEW_MASTER_PASSWORD: &str = "new correct horse battery staple";

    const ROOT_AAD: &[u8] = b"pm:v1:ark:crypto-profile:test-profile:key-version:1";

    const RECOVERY_AAD: &[u8] = b"pm:v1:recovery-ark:crypto-profile:test-profile:key-version:1";

    const VAULT_AAD: &[u8] = b"pm:v1:pvk:vault:test-vault:key-version:1";

    #[test]
    fn change_rewraps_the_same_root_key() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let current_mpk = Zeroizing::new(
            derive_master_password_key(OLD_MASTER_PASSWORD, &account_secret, &current_kdf_salt)
                .expect("current MPK derivation should succeed"),
        );

        let current_mkek = Zeroizing::new(
            derive_master_key_encryption_key(current_mpk.as_ref())
                .expect("current MKEK derivation should succeed"),
        );

        let original_root_key = Zeroizing::new(
            unwrap_key(current_mkek.as_ref(), &current_root_envelope, ROOT_AAD)
                .expect("original ARK should unwrap"),
        );

        let change = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("Master Password change should succeed");

        let new_mpk = Zeroizing::new(
            derive_master_password_key(NEW_MASTER_PASSWORD, &account_secret, &change.kdf_salt)
                .expect("new MPK derivation should succeed"),
        );

        let new_mkek = Zeroizing::new(
            derive_master_key_encryption_key(new_mpk.as_ref())
                .expect("new MKEK derivation should succeed"),
        );

        let changed_root_key = Zeroizing::new(
            unwrap_key(new_mkek.as_ref(), &change.root_key_envelope, ROOT_AAD)
                .expect("changed ARK should unwrap"),
        );

        assert_eq!(original_root_key.as_slice(), changed_root_key.as_slice(),);
    }

    #[test]
    fn new_master_password_unlocks_existing_vault() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let vault_envelope = bootstrap.vault_key_envelope();

        let change = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("Master Password change should succeed");

        let unlocked = unlock_personal_vault_inner(
            NEW_MASTER_PASSWORD,
            &account_secret,
            &change.kdf_salt,
            &change.root_key_envelope,
            ROOT_AAD,
            &vault_envelope,
            VAULT_AAD,
        )
        .expect("new Master Password should unlock existing vault");

        assert!(!unlocked.is_cleared());
    }

    #[test]
    fn old_master_password_cannot_unlock_changed_envelope() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let vault_envelope = bootstrap.vault_key_envelope();

        let change = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("Master Password change should succeed");

        let result = unlock_personal_vault_inner(
            OLD_MASTER_PASSWORD,
            &account_secret,
            &change.kdf_salt,
            &change.root_key_envelope,
            ROOT_AAD,
            &vault_envelope,
            VAULT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_current_master_password_cannot_change_password() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let result = change_master_password_inner(
            "wrong current password",
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_account_secret_cannot_change_password() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let wrong_account_secret = [0x42_u8; KEY_LENGTH];

        let result = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &wrong_account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_current_kdf_salt_cannot_change_password() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_root_envelope = bootstrap.root_key_envelope();

        let wrong_kdf_salt = [0x42_u8; KDF_SALT_LENGTH];

        let result = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &wrong_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_root_aad_cannot_change_password() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let result = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            b"wrong-root-context",
        );

        assert!(result.is_err());
    }

    #[test]
    fn change_generates_fresh_kdf_salt() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let first = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("first Master Password change should succeed");

        let second = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("second Master Password change should succeed");

        assert_ne!(first.kdf_salt, second.kdf_salt,);
    }

    #[test]
    fn change_generates_fresh_envelope_nonce() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let first = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("first Master Password change should succeed");

        let second = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("second Master Password change should succeed");

        /*
         * Envelope layout:
         *
         * byte 0      version
         * bytes 1..13 AES-GCM 96-bit nonce
         */
        assert_ne!(
            &first.root_key_envelope[1..13],
            &second.root_key_envelope[1..13],
        );
    }

    #[test]
    fn clear_zeroizes_change_result() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let account_secret = bootstrap.account_secret();

        let current_kdf_salt = bootstrap.kdf_salt();

        let current_root_envelope = bootstrap.root_key_envelope();

        let mut change = change_master_password_inner(
            OLD_MASTER_PASSWORD,
            NEW_MASTER_PASSWORD,
            &account_secret,
            &current_kdf_salt,
            &current_root_envelope,
            ROOT_AAD,
        )
        .expect("Master Password change should succeed");

        change.clear();

        assert_eq!(change.kdf_salt, [0_u8; KDF_SALT_LENGTH],);

        assert!(change.root_key_envelope.iter().all(|byte| *byte == 0),);
    }
}
