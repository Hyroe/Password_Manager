-- CreateEnum
CREATE TYPE "VaultItemChangeKind" AS ENUM ('CREATED', 'UPDATED', 'DELETED', 'RESTORED', 'SNAPSHOT');

-- CreateTable
CREATE TABLE "vault_item_changes" (
    "id" BIGSERIAL NOT NULL,
    "vault_id" UUID NOT NULL,
    "item_id" UUID NOT NULL,
    "revision_number" INTEGER NOT NULL,
    "kind" "VaultItemChangeKind" NOT NULL,
    "deleted_at" TIMESTAMPTZ(3),
    "changed_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_item_changes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "vault_item_changes_vault_id_id_idx" ON "vault_item_changes"("vault_id", "id");

-- CreateIndex
CREATE INDEX "vault_item_changes_item_id_id_idx" ON "vault_item_changes"("item_id", "id");

-- AddForeignKey
ALTER TABLE "vault_item_changes" ADD CONSTRAINT "vault_item_changes_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "vaults"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vault_item_changes" ADD CONSTRAINT "vault_item_changes_item_id_fkey" FOREIGN KEY ("item_id") REFERENCES "vault_items"("id") ON DELETE CASCADE ON UPDATE CASCADE;

INSERT INTO "vault_item_changes" (
  "vault_id",
  "item_id",
  "revision_number",
  "kind",
  "deleted_at",
  "changed_at"
)
SELECT
  "vault_id",
  "id",
  "current_revision_number",
  CASE
    WHEN "deleted_at" IS NULL
      THEN 'SNAPSHOT'::"VaultItemChangeKind"
    ELSE 'DELETED'::"VaultItemChangeKind"
  END,
  "deleted_at",
  "updated_at"
FROM "vault_items"
WHERE "current_revision_number" > 0
ORDER BY
  "updated_at",
  "id";
