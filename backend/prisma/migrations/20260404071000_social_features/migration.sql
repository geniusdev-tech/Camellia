-- CreateEnum
CREATE TYPE "ReactionType" AS ENUM ('like', 'insight', 'celebrate');

-- CreateTable
CREATE TABLE "social_posts" (
    "id" TEXT NOT NULL,
    "release_id" TEXT NOT NULL,
    "author_id" TEXT,
    "content" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "social_posts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "social_reactions" (
    "id" TEXT NOT NULL,
    "post_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "reaction_type" "ReactionType" NOT NULL DEFAULT 'like',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "social_reactions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "social_comments" (
    "id" TEXT NOT NULL,
    "post_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "social_comments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "social_bookmarks" (
    "id" TEXT NOT NULL,
    "post_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "social_bookmarks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "social_reposts" (
    "id" TEXT NOT NULL,
    "post_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "social_reposts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "social_communities" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "social_communities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "social_community_members" (
    "id" TEXT NOT NULL,
    "community_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "social_community_members_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "social_posts_release_id_key" ON "social_posts"("release_id");
CREATE INDEX "social_posts_created_at_idx" ON "social_posts"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "social_reactions_post_id_user_id_key" ON "social_reactions"("post_id", "user_id");
CREATE INDEX "social_reactions_post_id_reaction_type_idx" ON "social_reactions"("post_id", "reaction_type");

-- CreateIndex
CREATE INDEX "social_comments_post_id_created_at_idx" ON "social_comments"("post_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "social_bookmarks_post_id_user_id_key" ON "social_bookmarks"("post_id", "user_id");
CREATE INDEX "social_bookmarks_user_id_created_at_idx" ON "social_bookmarks"("user_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "social_reposts_post_id_user_id_key" ON "social_reposts"("post_id", "user_id");
CREATE INDEX "social_reposts_post_id_created_at_idx" ON "social_reposts"("post_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "social_communities_slug_key" ON "social_communities"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "social_community_members_community_id_user_id_key" ON "social_community_members"("community_id", "user_id");
CREATE INDEX "social_community_members_user_id_created_at_idx" ON "social_community_members"("user_id", "created_at");

-- AddForeignKey
ALTER TABLE "social_posts"
  ADD CONSTRAINT "social_posts_release_id_fkey"
  FOREIGN KEY ("release_id") REFERENCES "releases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_posts"
  ADD CONSTRAINT "social_posts_author_id_fkey"
  FOREIGN KEY ("author_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "social_reactions"
  ADD CONSTRAINT "social_reactions_post_id_fkey"
  FOREIGN KEY ("post_id") REFERENCES "social_posts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_reactions"
  ADD CONSTRAINT "social_reactions_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_comments"
  ADD CONSTRAINT "social_comments_post_id_fkey"
  FOREIGN KEY ("post_id") REFERENCES "social_posts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_comments"
  ADD CONSTRAINT "social_comments_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_bookmarks"
  ADD CONSTRAINT "social_bookmarks_post_id_fkey"
  FOREIGN KEY ("post_id") REFERENCES "social_posts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_bookmarks"
  ADD CONSTRAINT "social_bookmarks_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_reposts"
  ADD CONSTRAINT "social_reposts_post_id_fkey"
  FOREIGN KEY ("post_id") REFERENCES "social_posts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_reposts"
  ADD CONSTRAINT "social_reposts_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_community_members"
  ADD CONSTRAINT "social_community_members_community_id_fkey"
  FOREIGN KEY ("community_id") REFERENCES "social_communities"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "social_community_members"
  ADD CONSTRAINT "social_community_members_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
