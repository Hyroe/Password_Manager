import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const {
  generate_account_secret,
  generate_kdf_salt,
  generate_root_key,
  derive_master_password_key,
  derive_master_key_encryption_key,
  wrap_key,
  unwrap_key,
  create_account_bootstrap,
} = require('../pkg-node/pm_crypto_core.js');

function equalBytes(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((value, index) => value === right[index]);
}

const encoder = new TextEncoder();

const accountSecret = generate_account_secret();
const salt = generate_kdf_salt();
const ark = generate_root_key();

const mpk = derive_master_password_key(
  'correct horse battery staple',
  accountSecret,
  salt,
);

const mkek = derive_master_key_encryption_key(mpk);

const aad = encoder.encode(
  'pm:v1:ark:wasm-smoke-test:key-version:1',
);

const envelope = wrap_key(mkek, ark, aad);
const recoveredArk = unwrap_key(mkek, envelope, aad);

if (!equalBytes(ark, recoveredArk)) {
  throw new Error('Recovered ARK does not match original ARK');
}

console.log('WASM crypto smoke test passed');
console.log({
  accountSecretBytes: accountSecret.length,
  saltBytes: salt.length,
  arkBytes: ark.length,
  mpkBytes: mpk.length,
  mkekBytes: mkek.length,
  envelopeBytes: envelope.length,
  recoveredArkBytes: recoveredArk.length,
});

const wrongAad = encoder.encode(
  'pm:v1:ark:different-context:key-version:1',
);

let rejectedWrongContext = false;

try {
  unwrap_key(mkek, envelope, wrongAad);
} catch {
  rejectedWrongContext = true;
}

if (!rejectedWrongContext) {
  throw new Error('Envelope accepted incorrect AAD');
}

console.log('AAD tampering rejected correctly');


const cryptoProfileId =
  '0199c531-a830-7000-8000-000000000001';

const vaultId =
  '0199c531-a830-7000-8000-000000000002';

const rootAad = encoder.encode(
  `pm:v1:ark:crypto-profile:${cryptoProfileId}:key-version:1`,
);

const recoveryAad = encoder.encode(
  `pm:v1:recovery-ark:crypto-profile:${cryptoProfileId}:key-version:1`,
);

const vaultAad = encoder.encode(
  `pm:v1:pvk:vault:${vaultId}:key-version:1`,
);

const bootstrap = create_account_bootstrap(
  'correct horse battery staple',
  rootAad,
  recoveryAad,
  vaultAad,
);

const bootstrapAccountSecret =
  bootstrap.account_secret();

const bootstrapRecoveryKey =
  bootstrap.recovery_key();

const bootstrapSalt =
  bootstrap.kdf_salt();

const rootEnvelope =
  bootstrap.root_key_envelope();

const recoveryEnvelope =
  bootstrap.recovery_root_key_envelope();

const vaultEnvelope =
  bootstrap.vault_key_envelope();

console.log('Account bootstrap WASM test passed');

console.log({
  protocolVersion: bootstrap.protocol_version,
  kdfProfileVersion: bootstrap.kdf_profile_version,

  accountSecretBytes: bootstrapAccountSecret.length,
  recoveryKeyBytes: bootstrapRecoveryKey.length,
  saltBytes: bootstrapSalt.length,

  rootEnvelopeBytes: rootEnvelope.length,
  recoveryEnvelopeBytes: recoveryEnvelope.length,
  vaultEnvelopeBytes: vaultEnvelope.length,
});

bootstrapAccountSecret.fill(0);
bootstrapRecoveryKey.fill(0);

bootstrap.clear();
bootstrap.free();

/*
 * Best-effort cleanup of JS-visible copies.
 * This does not guarantee erasure of every historical WASM/JS copy.
 */
accountSecret.fill(0);
salt.fill(0);
ark.fill(0);
mpk.fill(0);
mkek.fill(0);
recoveredArk.fill(0);