/*
  Warnings:

  - You are about to drop the column `kdfAlgorithm` on the `user_crypto_profiles` table. All the data in the column will be lost.
  - Added the required column `kdf_algorithm` to the `user_crypto_profiles` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "user_crypto_profiles"
RENAME COLUMN "kdfAlgorithm" TO "kdf_algorithm";
