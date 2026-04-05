-- Alter users for GitHub OAuth support
ALTER TABLE "users"
  ALTER COLUMN "password_hash" DROP NOT NULL,
  ADD COLUMN "name" TEXT,
  ADD COLUMN "avatar_url" TEXT,
  ADD COLUMN "github_id" TEXT,
  ADD COLUMN "github_token" TEXT;

-- Unique index for GitHub account mapping
CREATE UNIQUE INDEX "users_github_id_key" ON "users"("github_id");

-- Cache table for GitHub repositories linked to each user
CREATE TABLE "github_repositories" (
  "id" TEXT NOT NULL,
  "github_id" INTEGER NOT NULL,
  "user_id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "full_name" TEXT NOT NULL,
  "description" TEXT,
  "html_url" TEXT NOT NULL,
  "language" TEXT,
  "stargazers" INTEGER NOT NULL DEFAULT 0,
  "forks" INTEGER NOT NULL DEFAULT 0,
  "db_created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "db_updated_at" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "github_repositories_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "github_repositories_github_id_key" ON "github_repositories"("github_id");
CREATE INDEX "github_repositories_user_id_idx" ON "github_repositories"("user_id");

ALTER TABLE "github_repositories"
  ADD CONSTRAINT "github_repositories_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
