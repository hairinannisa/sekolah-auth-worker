/**
 * googleAuth.ts — Tukar service account jadi access token OAuth2 (RFC 7523,
 * "JWT Bearer flow"), dipakai untuk otorisasi ke Firestore REST API dengan
 * privilese ADMIN (bypass firestore.rules sepenuhnya — makanya private_key
 * service account WAJIB cuma ada di secret Worker, TIDAK PERNAH di client).
 */
import { signRS256 } from './jwt';
import type { ServiceAccount } from './env';

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPE = 'https://www.googleapis.com/auth/datastore';

// Cache access token di scope module (berlaku ~1 jam) supaya tidak minta token
// baru di setiap request selama isolate Worker masih hangat.
let cachedToken: { value: string; expiresAt: number } | null = null;

export async function getFirestoreAccessToken(sa: ServiceAccount): Promise<string> {
  const now = Date.now();
  if (cachedToken && cachedToken.expiresAt - 60_000 > now) return cachedToken.value;

  const assertion = await signRS256(sa, {
    iss: sa.client_email,
    sub: sa.client_email,
    aud: TOKEN_URL,
    scope: SCOPE,
  }, 3600);

  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Gagal menukar service account ke access token (${res.status}): ${body}`);
  }
  const data = await res.json() as { access_token: string; expires_in: number };
  cachedToken = { value: data.access_token, expiresAt: now + data.expires_in * 1000 };
  return data.access_token;
}

