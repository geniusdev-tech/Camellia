-- Allow same GitHub repository id to be cached by multiple users
DROP INDEX "github_repositories_github_id_key";

CREATE UNIQUE INDEX "github_repositories_user_id_github_id_key"
  ON "github_repositories"("user_id", "github_id");

CREATE INDEX "github_repositories_github_id_idx"
  ON "github_repositories"("github_id");
