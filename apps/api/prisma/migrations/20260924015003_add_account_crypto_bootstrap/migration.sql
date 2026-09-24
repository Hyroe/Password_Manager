/*
  Warnings:

  - A unique constraint covering the columns `[completed_user_id]` on the table `registration_attempts` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[webauthn_user_id]` on the table `users` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `webauthn_user_id` to the `users` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "KdfAlgorithm" AS ENUM ('ARGON2ID');

-- CreateEnum
CREATE TYPE "VaultKind" AS ENUM ('PERSONAL');

-- AlterTable
ALTER TABLE "registration_attempts" ADD COLUMN     "completed_at" TIMESTAMPTZ(3),
ADD COLUMN     "completed_user_id" UUID;

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "webauthn_user_id" VARCHAR(128) NOT NULL;

-- CreateTable
CREATE TABLE "passkey_credentials" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "credential_id" TEXT NOT NULL,
    "public_key" BYTEA NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "device_type" VARCHAR(32) NOT NULL,
    "backed_up" BOOLEAN NOT NULL,
    "transports" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_used_at" TIMESTAMPTZ(3),

    CONSTRAINT "passkey_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_crypto_profiles" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "protocol_version" INTEGER NOT NULL,
    "kdfAlgorithm" "KdfAlgorithm" NOT NULL,
    "kdf_profile_version" INTEGER NOT NULL,
    "argon2_memory_kib" INTEGER NOT NULL,
    "argon2_iterations" INTEGER NOT NULL,
    "argon2_parallelism" INTEGER NOT NULL,
    "kdf_salt" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "user_crypto_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "root_key_envelopes" (
    "id" UUID NOT NULL,
    "crypto_profile_id" UUID NOT NULL,
    "key_version" INTEGER NOT NULL,
    "envelope_version" INTEGER NOT NULL,
    "encrypted_key" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "root_key_envelopes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "recovery_envelopes" (
    "id" UUID NOT NULL,
    "crypto_profile_id" UUID NOT NULL,
    "recovery_version" INTEGER NOT NULL,
    "root_key_version" INTEGER NOT NULL,
    "envelope_version" INTEGER NOT NULL,
    "encrypted_key" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "recovery_envelopes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vaults" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "kind" "VaultKind" NOT NULL DEFAULT 'PERSONAL',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "vaults_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vault_key_envelopes" (
    "id" UUID NOT NULL,
    "vault_id" UUID NOT NULL,
    "vault_key_version" INTEGER NOT NULL,
    "root_key_version" INTEGER NOT NULL,
    "envelope_version" INTEGER NOT NULL,
    "encrypted_key" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "vault_key_envelopes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account_bootstrap_contexts" (
    "id" UUID NOT NULL,
    "registration_attempt_id" UUID NOT NULL,
    "crypto_profile_id" UUID NOT NULL,
    "personal_vault_id" UUID NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "account_bootstrap_contexts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "passkey_credentials_credential_id_key" ON "passkey_credentials"("credential_id");

-- CreateIndex
CREATE INDEX "passkey_credentials_user_id_idx" ON "passkey_credentials"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "user_crypto_profiles_user_id_key" ON "user_crypto_profiles"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "root_key_envelopes_crypto_profile_id_key_version_key" ON "root_key_envelopes"("crypto_profile_id", "key_version");

-- CreateIndex
CREATE UNIQUE INDEX "recovery_envelopes_crypto_profile_id_recovery_version_key" ON "recovery_envelopes"("crypto_profile_id", "recovery_version");

-- CreateIndex
CREATE INDEX "vaults_user_id_idx" ON "vaults"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "vault_key_envelopes_vault_id_vault_key_version_key" ON "vault_key_envelopes"("vault_id", "vault_key_version");

-- CreateIndex
CREATE UNIQUE INDEX "account_bootstrap_contexts_registration_attempt_id_key" ON "account_bootstrap_contexts"("registration_attempt_id");

-- CreateIndex
CREATE INDEX "account_bootstrap_contexts_expires_at_idx" ON "account_bootstrap_contexts"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "registration_attempts_completed_user_id_key" ON "registration_attempts"("completed_user_id");

-- CreateIndex
CREATE UNIQUE INDEX "users_webauthn_user_id_key" ON "users"("webauthn_user_id");

-- AddForeignKey
ALTER TABLE "passkey_credentials" ADD CONSTRAINT "passkey_credentials_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_crypto_profiles" ADD CONSTRAINT "user_crypto_profiles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "root_key_envelopes" ADD CONSTRAINT "root_key_envelopes_crypto_profile_id_fkey" FOREIGN KEY ("crypto_profile_id") REFERENCES "user_crypto_profiles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recovery_envelopes" ADD CONSTRAINT "recovery_envelopes_crypto_profile_id_fkey" FOREIGN KEY ("crypto_profile_id") REFERENCES "user_crypto_profiles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vaults" ADD CONSTRAINT "vaults_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vault_key_envelopes" ADD CONSTRAINT "vault_key_envelopes_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "vaults"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "registration_attempts" ADD CONSTRAINT "registration_attempts_completed_user_id_fkey" FOREIGN KEY ("completed_user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_bootstrap_contexts" ADD CONSTRAINT "account_bootstrap_contexts_registration_attempt_id_fkey" FOREIGN KEY ("registration_attempt_id") REFERENCES "registration_attempts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
