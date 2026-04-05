export interface ApiResponse {
  success: boolean
  msg?: string
  message?: string
  error?: string | null
  [key: string]: unknown
}

export interface LoginRequest {
  email: string
  password: string
}

export interface RegisterRequest {
  email: string
  password: string
}

export interface LoginMFARequest {
  code: string
  user_id: number | string
}

export interface Verify2FARequest {
  code: string
}

export interface AuthUser {
  user_id?: number | string
  id?: string
  email: string
  name?: string | null
  avatarUrl?: string | null
  github_id?: string | null
  githubId?: string | null
  has_2fa: boolean
  role?: string | null
}

export interface LoginResponse extends ApiResponse {
  access_token?: string
  accessToken?: string
  refresh_token?: string
  email?: string
  name?: string | null
  avatarUrl?: string | null
  github_id?: string | null
  has_2fa?: boolean
  role?: string | null
  requires_mfa?: boolean
  requires_2fa?: boolean
  user_id?: number | string
}

export interface Setup2FAResponse extends ApiResponse {
  secret: string
  qr_code: string
}

export interface ShareGrant {
  user_id: number
  grant_role: string
  expires_at?: string | null
  created_at?: string
}

export interface TeamGrant {
  team_id: string
  grant_role: string
  expires_at?: string | null
  created_at?: string
}

export interface ProjectHistoryEvent {
  id: string
  project_id: string
  actor_user_id: number
  from_status?: string | null
  to_status: string
  reason?: string | null
  created_at: string
}

export interface RepositoryProject {
  id: string
  user_id: number
  package_name: string
  package_version: string
  filename: string
  description?: string | null
  changelog?: string | null
  content_type?: string | null
  size_bytes: number
  uncompressed_size_bytes: number
  zip_entry_count: number
  checksum_sha256: string
  storage_key: string
  bucket: string
  visibility: 'private' | 'public' | 'shared'
  lifecycle_status: 'draft' | 'submitted' | 'approved' | 'published' | 'archived' | 'rejected'
  status_reason?: string | null
  is_latest: boolean
  shared_with: number[]
  share_grants: ShareGrant[]
  team_grants: TeamGrant[]
  metadata: Record<string, unknown>
  duplicate_of_id?: string | null
  download_count: number
  reviewed_by?: number | null
  reviewed_at?: string | null
  submitted_at?: string | null
  approved_at?: string | null
  published_at?: string | null
  archived_at?: string | null
  rejected_at?: string | null
  created_at: string
}

export interface ProjectListResponse extends ApiResponse {
  projects: RepositoryProject[]
  pagination: {
    page: number
    page_size: number
    total: number
    pages: number
  }
}

export interface ProjectUploadResponse extends ApiResponse {
  project?: RepositoryProject
  deduplicated?: boolean
  scan_job_id?: string
}

export interface ProjectDetailResponse extends ApiResponse {
  project: RepositoryProject
  history: ProjectHistoryEvent[]
}

export interface ProjectHistoryResponse extends ApiResponse {
  history: ProjectHistoryEvent[]
}

export interface PackageVersionMatrixResponse extends ApiResponse {
  package_name: string
  versions: RepositoryProject[]
}

export interface TeamMember {
  user_id: number
  role: string
  created_at: string
}

export interface Team {
  id: string
  name: string
  owner_user_id: number
  created_at: string
  members: TeamMember[]
}

export interface TeamListResponse extends ApiResponse {
  teams: Team[]
}

export interface TeamCreateResponse extends ApiResponse {
  team: Team
}

export interface TeamInvite {
  id: string
  team_id: string
  email: string
  role: string
  token: string
  expires_at?: string | null
  accepted_at?: string | null
}

export interface TeamInviteResponse extends ApiResponse {
  invite: TeamInvite
}

export interface ShareGrantInput {
  user_id: number
  grant_role: string
  expires_at?: string | null
}

export interface AsyncJob {
  id: string
  job_type: string
  status: string
  priority: number
  payload: Record<string, unknown>
  result: Record<string, unknown>
  error_message?: string | null
  attempts: number
  project_id?: string | null
  created_by_user_id?: number | null
  started_at?: string | null
  finished_at?: string | null
  created_at: string
}

export interface AsyncJobResponse extends ApiResponse {
  job: AsyncJob
}

export interface AsyncJobListResponse extends ApiResponse {
  jobs: AsyncJob[]
}

export interface MetricsSnapshot {
  requests: Record<string, number>
  latency_ms: Record<string, { count: number; avg: number; max: number }>
}

export interface MetricsResponse extends ApiResponse {
  metrics: MetricsSnapshot
}

export interface PublicPackageListResponse extends ApiResponse {
  packages: RepositoryProject[]
  pagination: {
    page: number
    page_size: number
    total: number
    pages: number
  }
}

export interface PublicPackageDetailResponse extends ApiResponse {
  package_name: string
  latest: RepositoryProject
  versions: RepositoryProject[]
}

export interface PublicLatestResponse extends ApiResponse {
  package_name: string
  release: RepositoryProject
}

export interface PublicVersionResponse extends ApiResponse {
  release: RepositoryProject
}

export interface DownloadResponse extends ApiResponse {
  download_url: string
  expires_in: number
  project?: RepositoryProject
  release?: RepositoryProject
}

export type ReleaseChannel = 'alpha' | 'beta' | 'stable'
export type DeploymentEnv = 'dev' | 'staging' | 'prod'
export type ReleaseStatus = 'draft' | 'scan_pending' | 'scan_failed' | 'approved' | 'published' | 'rollbacked'

export interface GateRelease {
  id: string
  packageName: string
  packageVersion: string
  releaseChannel: ReleaseChannel
  deploymentEnv: DeploymentEnv
  status: ReleaseStatus
  maxCvss: number
  complianceScore: number
  riskScore: number
  policyApproved: boolean
  rollbackOfId?: string | null
  metadataJson?: string | null
  createdAt: string
  updatedAt: string
}

export interface ReleasesListResponse extends ApiResponse {
  releases: GateRelease[]
}

export interface CreateReleaseRequest {
  packageName: string
  packageVersion: string
  releaseChannel: ReleaseChannel
  deploymentEnv: DeploymentEnv
  maxCvss: number
  complianceScore: number
  riskScore: number
  metadata?: Record<string, unknown>
}

export interface CreateReleaseResponse extends ApiResponse {
  release: GateRelease
}

export type SocialReactionType = 'like' | 'insight' | 'celebrate'

export interface SocialFeedPost {
  id: string
  createdAt: string
  content: string
  release: {
    id: string
    packageName: string
    packageVersion: string
    releaseChannel: string
    deploymentEnv: string
    status: string
  }
  author: { id: string; email: string } | null
  stats: {
    reactions: Record<SocialReactionType, number>
    comments: number
    reposts: number
    bookmarks: number
  }
  viewer: {
    reactionType: SocialReactionType | null
    bookmarked: boolean
    reposted: boolean
  }
}

export interface SocialFeedResponse extends ApiResponse {
  posts: SocialFeedPost[]
}

export interface SocialSidebarCommunity {
  id: string
  slug: string
  name: string
  description?: string | null
  members: number
  joined: boolean
}

export interface SocialSidebarTrend {
  tag: string
  count: number
}

export interface SocialSuggestedUser {
  id: string
  email: string
  role: string
}

export interface SocialSidebarResponse extends ApiResponse {
  communities: SocialSidebarCommunity[]
  trends: SocialSidebarTrend[]
  suggestedUsers: SocialSuggestedUser[]
}

export interface GithubRepository {
  id: string
  githubId: number
  userId: string
  name: string
  fullName: string
  description?: string | null
  htmlUrl: string
  language?: string | null
  stargazers: number
  forks: number
  dbCreatedAt: string
  dbUpdatedAt: string
}

export interface GithubReposResponse extends ApiResponse {
  count: number
  repos: GithubRepository[]
}

export interface GithubProfile {
  githubId: number
  login: string
  name?: string | null
  avatarUrl: string
  bio?: string | null
  company?: string | null
  location?: string | null
  blog?: string | null
  htmlUrl: string
  followers: number
  following: number
  publicRepos: number
}

export interface GithubProfileResponse extends ApiResponse {
  profile: GithubProfile
}
