/*
  Warnings:

  - A unique constraint covering the columns `[vault_id,version]` on the table `vault_item_changes` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "vault_item_changes_vault_id_id_idx";

-- AlterTable
ALTER TABLE "vault_item_changes" ADD COLUMN     "version" BIGINT;

-- AlterTable
ALTER TABLE "vaults" ADD COLUMN     "sync_version" BIGINT NOT NULL DEFAULT 0;

WITH ranked_changes AS (
    SELECT
        "id",
        ROW_NUMBER() OVER (
            PARTITION BY "vault_id"
            ORDER BY "id"
        ) AS "version"
    FROM "vault_item_changes"
)
UPDATE "vault_item_changes" AS changes
SET "version" = ranked_changes."version"
FROM ranked_changes
WHERE changes."id" = ranked_changes."id";

UPDATE "vaults" AS vault
SET "sync_version" = versions."max_version"
FROM (
    SELECT
        "vault_id",
        MAX("version") AS "max_version"
    FROM "vault_item_changes"
    GROUP BY "vault_id"
) AS versions
WHERE vault."id" = versions."vault_id";

ALTER TABLE "vault_item_changes"
ALTER COLUMN "version" SET NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "vault_item_changes_vault_id_version_key" ON "vault_item_changes"("vault_id", "version");
