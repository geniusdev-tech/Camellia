-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('admin', 'writer', 'reader');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "role" "UserRole" NOT NULL DEFAULT 'reader',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- AlterTable
ALTER TABLE "releases" ADD COLUMN "policy_approved" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "releases" ADD COLUMN "rollback_of_id" TEXT;
