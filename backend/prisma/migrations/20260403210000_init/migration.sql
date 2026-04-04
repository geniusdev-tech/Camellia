-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "ReleaseChannel" AS ENUM ('alpha', 'beta', 'stable');

-- CreateEnum
CREATE TYPE "DeploymentEnv" AS ENUM ('dev', 'staging', 'prod');

-- CreateEnum
CREATE TYPE "ReleaseStatus" AS ENUM ('draft', 'approved', 'published', 'archived');

-- CreateTable
CREATE TABLE "releases" (
    "id" TEXT NOT NULL,
    "package_name" TEXT NOT NULL,
    "package_version" TEXT NOT NULL,
    "release_channel" "ReleaseChannel" NOT NULL DEFAULT 'stable',
    "deployment_env" "DeploymentEnv" NOT NULL DEFAULT 'dev',
    "status" "ReleaseStatus" NOT NULL DEFAULT 'draft',
    "max_cvss" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "compliance_score" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "risk_score" DOUBLE PRECISION NOT NULL DEFAULT 100,
    "metadata_json" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "releases_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "releases_package_name_package_version_idx" ON "releases"("package_name", "package_version");

-- CreateIndex
CREATE INDEX "releases_package_name_release_channel_status_idx" ON "releases"("package_name", "release_channel", "status");

-- CreateIndex
CREATE UNIQUE INDEX "releases_package_name_package_version_key" ON "releases"("package_name", "package_version");

