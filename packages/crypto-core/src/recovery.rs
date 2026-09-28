use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    envelope::{unwrap_key, wrap_key},
    kdf::{
        ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, KDF_PROFILE_VERSION,
        KDF_SALT_LENGTH, KEY_LENGTH, derive_master_key_encryption_key, derive_master_password_key,
        derive_recovery_key_encryption_key,
    },
};

const PROTOCOL_VERSION: u32 = 1;

fn generate_kdf_salt() -> Result<[u8; KDF_SALT_LENGTH], &'static str> {
    let mut salt = [0_u8; KDF_SALT_LENGTH];

    getrandom::fill(&mut salt).map_err(|_| "Secure random generation failed")?;

    Ok(salt)
}

#[wasm_bindgen]
pub struct MasterPasswordRecoveryResult {
    kdf_salt: [u8; KDF_SALT_LENGTH],
    root_key_envelope: Vec<u8>,
}

#[wasm_bindgen]
impl MasterPasswordRecoveryResult {
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

impl Drop for MasterPasswordRecoveryResult {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) fn recover_master_password_inner(
    new_master_password: &str,
    account_secret: &[u8],
    recovery_key: &[u8],
    recovery_root_key_envelope: &[u8],
    recovery_root_key_aad: &[u8],
    root_key_aad: &[u8],
) -> Result<MasterPasswordRecoveryResult, &'static str> {
    if new_master_password.is_empty() {
        return Err("New Master Password must not be empty");
    }

    if account_secret.len() != KEY_LENGTH {
        return Err("Account Secret must be exactly 32 bytes");
    }

    if recovery_key.len() != KEY_LENGTH {
        return Err("Recovery Key must be exactly 32 bytes");
    }

    if recovery_root_key_aad.is_empty() || root_key_aad.is_empty() {
        return Err("Key envelope AAD must not be empty");
    }

    /*
     * Recovery Key
     *     ↓ HKDF
     * Recovery KEK
     *     ↓ unwrap
     * existing ARK
     *
     * ARK never leaves this Rust function.
     */
    let recovery_key_encryption_key =
        Zeroizing::new(derive_recovery_key_encryption_key(recovery_key)?);

    let root_key = Zeroizing::new(unwrap_key(
        recovery_key_encryption_key.as_ref(),
        recovery_root_key_envelope,
        recovery_root_key_aad,
    )?);

    if root_key.len() != KEY_LENGTH {
        return Err("Invalid root key length");
    }

    /*
     * Recovery deliberately creates a fresh KDF salt.
     *
     * New Master Password + Account Secret + new salt
     *     ↓ Argon2id
     * MPK
     *     ↓ HKDF
     * new MKEK
     */
    let kdf_salt = generate_kdf_salt()?;

    let master_password_key = Zeroizing::new(derive_master_password_key(
        new_master_password,
        account_secret,
        &kdf_salt,
    )?);

    let master_key_encryption_key = Zeroizing::new(derive_master_key_encryption_key(
        master_password_key.as_ref(),
    )?);

    /*
     * Re-wrap the SAME ARK.
     *
     * PVK and all item keys remain untouched.
     */
    let root_key_envelope = wrap_key(
        master_key_encryption_key.as_ref(),
        root_key.as_slice(),
        root_key_aad,
    )?;

    Ok(MasterPasswordRecoveryResult {
        kdf_salt,
        root_key_envelope,
    })
}

#[wasm_bindgen]
pub fn recover_master_password(
    new_master_password: &str,
    account_secret: &[u8],
    recovery_key: &[u8],
    recovery_root_key_envelope: &[u8],
    recovery_root_key_aad: &[u8],
    root_key_aad: &[u8],
) -> Result<MasterPasswordRecoveryResult, JsError> {
    recover_master_password_inner(
        new_master_password,
        account_secret,
        recovery_key,
        recovery_root_key_envelope,
        recovery_root_key_aad,
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
        kdf::{
            derive_master_key_encryption_key, derive_master_password_key,
            derive_recovery_key_encryption_key,
        },
        unlock::unlock_personal_vault_inner,
    };

    const OLD_MASTER_PASSWORD: &str = "correct horse battery staple";
    const NEW_MASTER_PASSWORD: &str = "new correct horse battery staple";

    const ROOT_AAD: &[u8] = b"pm:v1:ark:crypto-profile:test-profile:key-version:1";

    const RECOVERY_AAD: &[u8] = b"pm:v1:recovery-ark:crypto-profile:test-profile:key-version:1";

    const VAULT_AAD: &[u8] = b"pm:v1:pvk:vault:test-vault:key-version:1";

    #[test]
    fn recovery_rewraps_the_same_root_key() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let recovery = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("recovery should succeed");

        let recovery_kek = Zeroizing::new(
            derive_recovery_key_encryption_key(&bootstrap.recovery_key())
                .expect("Recovery KEK derivation should succeed"),
        );

        let original_root_key = Zeroizing::new(
            unwrap_key(
                recovery_kek.as_ref(),
                &bootstrap.recovery_root_key_envelope(),
                RECOVERY_AAD,
            )
            .expect("original ARK should unwrap"),
        );

        let new_mpk = Zeroizing::new(
            derive_master_password_key(
                NEW_MASTER_PASSWORD,
                &bootstrap.account_secret(),
                &recovery.kdf_salt,
            )
            .expect("new MPK derivation should succeed"),
        );

        let new_mkek = Zeroizing::new(
            derive_master_key_encryption_key(new_mpk.as_ref())
                .expect("new MKEK derivation should succeed"),
        );

        let recovered_root_key = Zeroizing::new(
            unwrap_key(new_mkek.as_ref(), &recovery.root_key_envelope, ROOT_AAD)
                .expect("recovered ARK should unwrap"),
        );

        assert_eq!(original_root_key.as_slice(), recovered_root_key.as_slice(),);
    }

    #[test]
    fn new_master_password_unlocks_existing_vault() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let recovery = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("recovery should succeed");

        let unlocked = unlock_personal_vault_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &recovery.kdf_salt,
            &recovery.root_key_envelope,
            ROOT_AAD,
            &bootstrap.vault_key_envelope(),
            VAULT_AAD,
        )
        .expect("new Master Password should unlock existing vault");

        assert!(!unlocked.is_cleared());
    }

    #[test]
    fn old_master_password_cannot_unlock_recovered_envelope() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let recovery = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("recovery should succeed");

        let result = unlock_personal_vault_inner(
            OLD_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &recovery.kdf_salt,
            &recovery.root_key_envelope,
            ROOT_AAD,
            &bootstrap.vault_key_envelope(),
            VAULT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_recovery_key_cannot_recover_root_key() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let wrong_recovery_key = [0x42_u8; KEY_LENGTH];

        let result = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &wrong_recovery_key,
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_recovery_aad_cannot_recover_root_key() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let result = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            b"wrong-recovery-context",
            ROOT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn wrong_account_secret_produces_envelope_that_correct_secret_cannot_unlock() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let wrong_account_secret = [0x24_u8; KEY_LENGTH];

        /*
         * Recovery Key can still recover the ARK.
         *
         * But using the wrong Account Secret derives
         * a different MPK/MKEK for the new envelope.
         */
        let recovery = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &wrong_account_secret,
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("ARK recovery itself should succeed");

        let result = unlock_personal_vault_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &recovery.kdf_salt,
            &recovery.root_key_envelope,
            ROOT_AAD,
            &bootstrap.vault_key_envelope(),
            VAULT_AAD,
        );

        assert!(result.is_err());
    }

    #[test]
    fn recovery_generates_fresh_kdf_salt() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let first = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("first recovery should succeed");

        let second = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("second recovery should succeed");

        assert_ne!(first.kdf_salt, second.kdf_salt,);
    }

    #[test]
    fn recovery_generates_fresh_envelope_nonce() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let first = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("first recovery should succeed");

        let second = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("second recovery should succeed");

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
    fn clear_zeroizes_recovery_result() {
        let bootstrap =
            create_account_bootstrap_inner(OLD_MASTER_PASSWORD, ROOT_AAD, RECOVERY_AAD, VAULT_AAD)
                .expect("bootstrap should succeed");

        let mut recovery = recover_master_password_inner(
            NEW_MASTER_PASSWORD,
            &bootstrap.account_secret(),
            &bootstrap.recovery_key(),
            &bootstrap.recovery_root_key_envelope(),
            RECOVERY_AAD,
            ROOT_AAD,
        )
        .expect("recovery should succeed");

        recovery.clear();

        assert_eq!(recovery.kdf_salt, [0_u8; KDF_SALT_LENGTH],);

        assert!(recovery.root_key_envelope.iter().all(|byte| *byte == 0),);
    }
}
