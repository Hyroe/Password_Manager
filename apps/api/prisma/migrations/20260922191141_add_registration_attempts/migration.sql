-- CreateEnum
CREATE TYPE "RegistrationStatus" AS ENUM ('PENDING', 'EMAIL_VERIFIED', 'COMPLETED', 'EXPIRED');

-- CreateTable
CREATE TABLE "registration_attempts" (
    "id" UUID NOT NULL,
    "email" VARCHAR(320) NOT NULL,
    "normalized_email" VARCHAR(320) NOT NULL,
    "status" "RegistrationStatus" NOT NULL DEFAULT 'PENDING',
    "email_token_hash" BYTEA NOT NULL,
    "email_token_expires_at" TIMESTAMPTZ(3) NOT NULL,
    "email_verified_at" TIMESTAMPTZ(3),
    "registration_token_hash" BYTEA,
    "registration_token_expires_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "registration_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "registration_attempts_normalized_email_idx" ON "registration_attempts"("normalized_email");

-- CreateIndex
CREATE INDEX "registration_attempts_status_email_token_expires_at_idx" ON "registration_attempts"("status", "email_token_expires_at");
