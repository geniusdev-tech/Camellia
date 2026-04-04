function firstNonEmpty(...values: Array<string | undefined>): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) return value.trim();
  }
  return undefined;
}

function isPlaceholderDatabaseUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const parsed = new URL(value);
    const host = parsed.hostname.toLowerCase();
    return ['postgres', 'db', 'localhost', '127.0.0.1'].includes(host);
  } catch {
    return false;
  }
}

function buildDatabaseUrlFromPgVars(): string | undefined {
  const host = firstNonEmpty(process.env.PGHOST);
  const port = firstNonEmpty(process.env.PGPORT) ?? '5432';
  const user = firstNonEmpty(process.env.PGUSER);
  const password = firstNonEmpty(process.env.PGPASSWORD);
  const database = firstNonEmpty(process.env.PGDATABASE);

  if (!host || !user || !password || !database) return undefined;

  const params = new URLSearchParams();
  const explicitSslMode = firstNonEmpty(process.env.PGSSLMODE);
  if (explicitSslMode) {
    params.set('sslmode', explicitSslMode);
  } else if (!['localhost', '127.0.0.1'].includes(host)) {
    params.set('sslmode', 'require');
  }

  const query = params.toString();
  const encodedUser = encodeURIComponent(user);
  const encodedPassword = encodeURIComponent(password);
  const encodedDatabase = encodeURIComponent(database);
  const base = `postgresql://${encodedUser}:${encodedPassword}@${host}:${port}/${encodedDatabase}`;
  return query ? `${base}?${query}` : base;
}

const currentDatabaseUrl = firstNonEmpty(process.env.DATABASE_URL);
const fallbackUrl = firstNonEmpty(
  process.env.DATABASE_PRIVATE_URL,
  process.env.POSTGRES_URL,
  process.env.POSTGRESQL_URL,
  buildDatabaseUrlFromPgVars(),
);

const isRailwayRuntime = Boolean(firstNonEmpty(process.env.RAILWAY_ENVIRONMENT, process.env.RAILWAY_PROJECT_ID));
const shouldReplacePlaceholder = isRailwayRuntime && isPlaceholderDatabaseUrl(currentDatabaseUrl) && Boolean(fallbackUrl);

if ((!currentDatabaseUrl && fallbackUrl) || shouldReplacePlaceholder) {
  process.env.DATABASE_URL = fallbackUrl;
}
