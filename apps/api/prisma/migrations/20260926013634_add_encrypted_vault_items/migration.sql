-- CreateTable
CREATE TABLE "vault_items" (
    "id" UUID NOT NULL,
    "vault_id" UUID NOT NULL,
    "current_revision_number" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "deleted_at" TIMESTAMPTZ(3),

    CONSTRAINT "vault_items_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vault_item_revisions" (
    "id" UUID NOT NULL,
    "item_id" UUID NOT NULL,
    "revision_number" INTEGER NOT NULL,
    "payload_version" INTEGER NOT NULL,
    "ciphertext_version" INTEGER NOT NULL,
    "ciphertext" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_item_revisions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "item_key_envelopes" (
    "id" UUID NOT NULL,
    "revision_id" UUID NOT NULL,
    "item_key_version" INTEGER NOT NULL,
    "vault_key_version" INTEGER NOT NULL,
    "envelope_version" INTEGER NOT NULL,
    "encrypted_key" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "item_key_envelopes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "vault_items_vault_id_deleted_at_idx" ON "vault_items"("vault_id", "deleted_at");

-- CreateIndex
CREATE INDEX "vault_items_vault_id_updated_at_idx" ON "vault_items"("vault_id", "updated_at");

-- CreateIndex
CREATE INDEX "vault_item_revisions_item_id_created_at_idx" ON "vault_item_revisions"("item_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "vault_item_revisions_item_id_revision_number_key" ON "vault_item_revisions"("item_id", "revision_number");

-- CreateIndex
CREATE INDEX "item_key_envelopes_revision_id_idx" ON "item_key_envelopes"("revision_id");

-- CreateIndex
CREATE UNIQUE INDEX "item_key_envelopes_revision_id_vault_key_version_key" ON "item_key_envelopes"("revision_id", "vault_key_version");

-- AddForeignKey
ALTER TABLE "vault_items" ADD CONSTRAINT "vault_items_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "vaults"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vault_item_revisions" ADD CONSTRAINT "vault_item_revisions_item_id_fkey" FOREIGN KEY ("item_id") REFERENCES "vault_items"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "item_key_envelopes" ADD CONSTRAINT "item_key_envelopes_revision_id_fkey" FOREIGN KEY ("revision_id") REFERENCES "vault_item_revisions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
