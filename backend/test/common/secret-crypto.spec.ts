import { openSecret, sealSecret } from '../../nest-src/common/security/secret-crypto';

describe('secret-crypto', () => {
  it('seals and opens value with same key material', () => {
    const key = 'test_secret_that_is_at_least_32_chars_long';
    const plain = 'gho_example_token';

    const sealed = sealSecret(plain, key);
    expect(sealed.startsWith('v1:')).toBe(true);

    const opened = openSecret(sealed, key);
    expect(opened).toBe(plain);
  });

  it('returns null for invalid payload', () => {
    const opened = openSecret('plain-text-token', 'another_key_material');
    expect(opened).toBeNull();
  });
});
