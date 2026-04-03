import fetch from 'node-fetch';

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

export const uploadFileToSupabase = async (
  bucket: string,
  filename: string,
  fileBuffer: Buffer,
  contentType: string
) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    throw new Error("Supabase storage credentials are not configured");
  }

  const url = `${SUPABASE_URL.replace(/\/$/, '')}/storage/v1/object/${bucket}/${filename}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'apikey': SUPABASE_SERVICE_KEY,
      'Content-Type': contentType,
    },
    body: fileBuffer,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Supabase upload failed: ${response.status} ${text}`);
  }

  return await response.json();
};

export const createSignedDownloadUrl = async (
  bucket: string,
  storageKey: string,
  expiresIn: number = 900
) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    throw new Error("Supabase storage credentials are not configured");
  }

  const path = encodeURIComponent(storageKey.replace(/^\//, '')).replace(/%2F/g, '/');
  const url = `${SUPABASE_URL.replace(/\/$/, '')}/storage/v1/object/sign/${bucket}/${path}`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'apikey': SUPABASE_SERVICE_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ expiresIn }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Supabase signed URL failed: ${response.status} ${text}`);
  }

  const data = await response.json() as any;
  const signedPath = data.signedURL || data.signedUrl;
  if (!signedPath) {
    throw new Error("Supabase signed URL response missing signed URL");
  }

  if (signedPath.startsWith('http://') || signedPath.startsWith('https://')) {
    return signedPath;
  }
  return `${SUPABASE_URL.replace(/\/$/, '')}${signedPath}`;
};
