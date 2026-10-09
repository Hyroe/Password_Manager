-- CreateEnum
CREATE TYPE "SessionClientKind" AS ENUM ('WEB', 'BROWSER_EXTENSION');

-- AlterTable
ALTER TABLE "sessions" ADD COLUMN     "client_kind" "SessionClientKind" NOT NULL DEFAULT 'WEB';
