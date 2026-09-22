/*
  Warnings:

  - A unique constraint covering the columns `[webauthn_user_id]` on the table `registration_attempts` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateEnum
CREATE TYPE "WebAuthnChallengePurpose" AS ENUM ('REGISTER_PASSKEY', 'LOGIN', 'REAUTHENTICATE', 'ADD_PASSKEY');

-- AlterEnum
ALTER TYPE "RegistrationStatus" ADD VALUE 'PASSKEY_REGISTERED';

-- AlterTable
ALTER TABLE "registration_attempts" ADD COLUMN     "bootstrap_token_expires_at" TIMESTAMPTZ(3),
ADD COLUMN     "bootstrap_token_hash" BYTEA,
ADD COLUMN     "webauthn_user_id" VARCHAR(128);

-- CreateTable
CREATE TABLE "webauthn_challenges" (
    "id" UUID NOT NULL,
    "registration_attempt_id" UUID,
    "purpose" "WebAuthnChallengePurpose" NOT NULL,
    "challenge" VARCHAR(512) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webauthn_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "registration_passkeys" (
    "id" UUID NOT NULL,
    "registration_attempt_id" UUID NOT NULL,
    "credential_id" TEXT NOT NULL,
    "public_key" BYTEA NOT NULL,
    "counter" BIGINT NOT NULL DEFAULT 0,
    "webauthn_user_id" VARCHAR(128) NOT NULL,
    "device_type" VARCHAR(32) NOT NULL,
    "backed_up" BOOLEAN NOT NULL,
    "transports" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "registration_passkeys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "webauthn_challenges_registration_attempt_id_purpose_idx" ON "webauthn_challenges"("registration_attempt_id", "purpose");

-- CreateIndex
CREATE INDEX "webauthn_challenges_expires_at_idx" ON "webauthn_challenges"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "registration_passkeys_credential_id_key" ON "registration_passkeys"("credential_id");

-- CreateIndex
CREATE INDEX "registration_passkeys_registration_attempt_id_idx" ON "registration_passkeys"("registration_attempt_id");

-- CreateIndex
CREATE UNIQUE INDEX "registration_passkeys_registration_attempt_id_webauthn_user_key" ON "registration_passkeys"("registration_attempt_id", "webauthn_user_id");

-- CreateIndex
CREATE UNIQUE INDEX "registration_attempts_webauthn_user_id_key" ON "registration_attempts"("webauthn_user_id");

-- AddForeignKey
ALTER TABLE "webauthn_challenges" ADD CONSTRAINT "webauthn_challenges_registration_attempt_id_fkey" FOREIGN KEY ("registration_attempt_id") REFERENCES "registration_attempts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "registration_passkeys" ADD CONSTRAINT "registration_passkeys_registration_attempt_id_fkey" FOREIGN KEY ("registration_attempt_id") REFERENCES "registration_attempts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
