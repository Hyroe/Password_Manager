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