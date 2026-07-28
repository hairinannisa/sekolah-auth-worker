/**
 * jwt.ts — Helper penandatanganan JWT RS256 pakai private key service account.
 * Dipakai untuk DUA hal yang beda (lihat googleAuth.ts & customToken.ts):
 *   1. Menukar service account jadi access token OAuth2 (buat baca Firestore REST API)
 *   2. Menerbitkan Firebase custom auth token (buat signInWithCustomToken di client)
 * Keduanya sama-sama "JWT ditandatangani RS256 dengan private key service account",
 * cuma audience & claims-nya beda — jadi fungsi signing-nya di-share di sini.
 */
import { SignJWT, importPKCS8 } from 'jose';
import type { ServiceAccount } from './env';

let cachedPrivateKey: CryptoKey | null = null;
let cachedPrivateKeyRaw: string | null = null;

async function getPrivateKey(pem: string): Promise<CryptoKey> {
  // Cache di scope module — bertahan antar-request selama Worker "hangat" (isolate
  // belum di-recycle), menghindari re-import key (mahal) di setiap login.
  if (cachedPrivateKey && cachedPrivateKeyRaw === pem) return cachedPrivateKey;
  const key = await importPKCS8(pem, 'RS256');
  cachedPrivateKey = key;
  cachedPrivateKeyRaw = pem;
  return key;
}

export function parseServiceAccount(json: string): ServiceAccount {
  const parsed = JSON.parse(json);
  if (!parsed.project_id || !parsed.private_key || !parsed.client_email) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON tidak lengkap — pastikan berisi project_id, private_key, dan client_email.');
  }
  // private_key dari JSON service account punya literal "\n" (bukan newline asli)
  // kalau disimpan sebagai satu baris di secret — normalisasi di sini supaya PEM valid.
  return { ...parsed, private_key: parsed.private_key.replace(/\\n/g, '\n') };
}

export async function signRS256(sa: ServiceAccount, claims: Record<string, unknown>, expiresInSeconds: number): Promise<string> {
  const key = await getPrivateKey(sa.private_key);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(now + expiresInSeconds)
    .sign(key);
}

