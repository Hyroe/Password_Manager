use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    envelope::wrap_key,
    kdf::{
        ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, KDF_PROFILE_VERSION,
        KDF_SALT_LENGTH, KEY_LENGTH, derive_master_key_encryption_key, derive_master_password_key,
        derive_recovery_key_encryption_key,
    },
};

const PROTOCOL_VERSION: u32 = 1;

fn random_bytes<const N: usize>() -> Result<[u8; N], &'static str> {
    let mut bytes = [0_u8; N];

    getrandom::fill(&mut bytes).map_err(|_| "Secure random generation failed")?;

    Ok(bytes)
}

#[wasm_bindgen]
pub struct AccountBootstrapResult {
    account_secret: [u8; KEY_LENGTH],
    recovery_key: [u8; KEY_LENGTH],
    kdf_salt: [u8; KDF_SALT_LENGTH],

    root_key_envelope: Vec<u8>,
    recovery_root_key_envelope: Vec<u8>,
    vault_key_envelope: Vec<u8>,
}

#[wasm_bindgen]
impl AccountBootstrapResult {
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

    pub fn account_secret(&self) -> Box<[u8]> {
        self.account_secret.to_vec().into_boxed_slice()
    }

    pub fn recovery_key(&self) -> Box<[u8]> {
        self.recovery_key.to_vec().into_boxed_slice()
    }

    pub fn kdf_salt(&self) -> Box<[u8]> {
        self.kdf_salt.to_vec().into_boxed_slice()
    }

    pub fn root_key_envelope(&self) -> Box<[u8]> {
        self.root_key_envelope.clone().into_boxed_slice()
    }

    pub fn recovery_root_key_envelope(&self) -> Box<[u8]> {
        self.recovery_root_key_envelope.clone().into_boxed_slice()
    }

    pub fn vault_key_envelope(&self) -> Box<[u8]> {
        self.vault_key_envelope.clone().into_boxed_slice()
    }

    pub fn clear(&mut self) {
        self.account_secret.zeroize();
        self.recovery_key.zeroize();
        self.kdf_salt.zeroize();

        self.root_key_envelope.zeroize();
        self.recovery_root_key_envelope.zeroize();
        self.vault_key_envelope.zeroize();
    }
}

impl Drop for AccountBootstrapResult {
    fn drop(&mut self) {
        self.clear();
    }
}

pub fn create_account_bootstrap_inner(
    master_password: &str,
    root_key_aad: &[u8],
    recovery_root_key_aad: &[u8],
    vault_key_aad: &[u8],
) -> Result<AccountBootstrapResult, &'static str> {
    if master_password.is_empty() {
        return Err("Master Password must not be empty");
    }

    if root_key_aad.is_empty() || recovery_root_key_aad.is_empty() || vault_key_aad.is_empty() {
        return Err("Key envelope AAD must not be empty");
    }

    let account_secret = random_bytes::<KEY_LENGTH>()?;
    let recovery_key = random_bytes::<KEY_LENGTH>()?;
    let kdf_salt = random_bytes::<KDF_SALT_LENGTH>()?;

    let root_key = Zeroizing::new(random_bytes::<KEY_LENGTH>()?);

    let vault_key = Zeroizing::new(random_bytes::<KEY_LENGTH>()?);

    let master_password_key = Zeroizing::new(derive_master_password_key(
        master_password,
        &account_secret,
        &kdf_salt,
    )?);

    let master_key_encryption_key = Zeroizing::new(derive_master_key_encryption_key(
        master_password_key.as_ref(),
    )?);

    let recovery_key_encryption_key =
        Zeroizing::new(derive_recovery_key_encryption_key(&recovery_key)?);

    let root_key_envelope = wrap_key(
        master_key_encryption_key.as_ref(),
        root_key.as_ref(),
        root_key_aad,
    )?;

    let recovery_root_key_envelope = wrap_key(
        recovery_key_encryption_key.as_ref(),
        root_key.as_ref(),
        recovery_root_key_aad,
    )?;

    let vault_key_envelope = wrap_key(root_key.as_ref(), vault_key.as_ref(), vault_key_aad)?;

    Ok(AccountBootstrapResult {
        account_secret,
        recovery_key,
        kdf_salt,
        root_key_envelope,
        recovery_root_key_envelope,
        vault_key_envelope,
    })
}

#[wasm_bindgen]
pub fn create_account_bootstrap(
    master_password: &str,
    root_key_aad: &[u8],
    recovery_root_key_aad: &[u8],
    vault_key_aad: &[u8],
) -> Result<AccountBootstrapResult, JsError> {
    create_account_bootstrap_inner(
        master_password,
        root_key_aad,
        recovery_root_key_aad,
        vault_key_aad,
    )
    .map_err(JsError::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        envelope::unwrap_key,
        kdf::{
            derive_master_key_encryption_key, derive_master_password_key,
            derive_recovery_key_encryption_key,
        },
    };

    const ROOT_AAD: &[u8] = b"pm:v1:ark:crypto-profile:test-profile:key-version:1";

    const RECOVERY_AAD: &[u8] = b"pm:v1:recovery-ark:crypto-profile:test-profile:key-version:1";

    const VAULT_AAD: &[u8] = b"pm:v1:pvk:vault:test-vault:key-version:1";

    #[test]
    fn creates_complete_account_bootstrap() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        assert_eq!(bootstrap.account_secret.len(), 32);
        assert_eq!(bootstrap.recovery_key.len(), 32);
        assert_eq!(bootstrap.kdf_salt.len(), 16);

        assert_eq!(bootstrap.root_key_envelope.len(), 61);
        assert_eq!(bootstrap.recovery_root_key_envelope.len(), 61);
        assert_eq!(bootstrap.vault_key_envelope.len(), 61);
    }

    #[test]
    fn master_password_path_recovers_vault_key() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let mut mpk = derive_master_password_key(
            "correct horse battery staple",
            &bootstrap.account_secret,
            &bootstrap.kdf_salt,
        )
        .expect("MPK derivation should succeed");

        let mut mkek =
            derive_master_key_encryption_key(&mpk).expect("MKEK derivation should succeed");

        let mut root_key =
            unwrap_key(&mkek, &bootstrap.root_key_envelope, ROOT_AAD).expect("ARK should unwrap");

        let vault_key = unwrap_key(&root_key, &bootstrap.vault_key_envelope, VAULT_AAD)
            .expect("PVK should unwrap");

        assert_eq!(root_key.len(), KEY_LENGTH);
        assert_eq!(vault_key.len(), KEY_LENGTH);

        mpk.zeroize();
        mkek.zeroize();
        root_key.zeroize();
    }

    #[test]
    fn recovery_path_recovers_same_root_key() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let mut mpk = derive_master_password_key(
            "correct horse battery staple",
            &bootstrap.account_secret,
            &bootstrap.kdf_salt,
        )
        .expect("MPK derivation should succeed");

        let mut mkek =
            derive_master_key_encryption_key(&mpk).expect("MKEK derivation should succeed");

        let mut recovery_kek = derive_recovery_key_encryption_key(&bootstrap.recovery_key)
            .expect("Recovery KEK derivation should succeed");

        let root_from_password = unwrap_key(&mkek, &bootstrap.root_key_envelope, ROOT_AAD)
            .expect("password ARK should unwrap");

        let root_from_recovery = unwrap_key(
            &recovery_kek,
            &bootstrap.recovery_root_key_envelope,
            RECOVERY_AAD,
        )
        .expect("recovery ARK should unwrap");

        assert_eq!(root_from_password, root_from_recovery);

        mpk.zeroize();
        mkek.zeroize();
        recovery_kek.zeroize();
    }

    #[test]
    fn wrong_master_password_cannot_recover_root_key() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let mpk = derive_master_password_key(
            "wrong password",
            &bootstrap.account_secret,
            &bootstrap.kdf_salt,
        )
        .expect("MPK derivation should succeed");

        let mkek = derive_master_key_encryption_key(&mpk).expect("MKEK derivation should succeed");

        let result = unwrap_key(&mkek, &bootstrap.root_key_envelope, ROOT_AAD);

        assert!(result.is_err());
    }

    #[test]
    fn aad_prevents_envelope_rebinding() {
        let bootstrap = create_account_bootstrap_inner(
            "correct horse battery staple",
            ROOT_AAD,
            RECOVERY_AAD,
            VAULT_AAD,
        )
        .expect("bootstrap should succeed");

        let mpk = derive_master_password_key(
            "correct horse battery staple",
            &bootstrap.account_secret,
            &bootstrap.kdf_salt,
        )
        .expect("MPK derivation should succeed");

        let mkek = derive_master_key_encryption_key(&mpk).expect("MKEK derivation should succeed");

        let result = unwrap_key(
            &mkek,
            &bootstrap.root_key_envelope,
            b"pm:v1:ark:crypto-profile:attacker:key-version:1",
        );

        assert!(result.is_err());
    }
}
