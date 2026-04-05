import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'crypto';

const VERSION = 'v1';
const IV_LENGTH = 12;

function deriveKey(keyMaterial: string): Buffer {
  return createHash('sha256').update(keyMaterial).digest();
}

export function sealSecret(plainText: string, keyMaterial: string): string {
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(keyMaterial);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return `${VERSION}:${iv.toString('base64url')}:${encrypted.toString('base64url')}:${tag.toString('base64url')}`;
}

export function openSecret(cipherText: string, keyMaterial: string): string | null {
  const parts = cipherText.split(':');
  if (parts.length !== 4 || parts[0] !== VERSION) {
    return null;
  }

  try {
    const iv = Buffer.from(parts[1], 'base64url');
    const encrypted = Buffer.from(parts[2], 'base64url');
    const tag = Buffer.from(parts[3], 'base64url');
    const key = deriveKey(keyMaterial);

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}
