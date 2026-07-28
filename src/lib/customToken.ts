/**
 * customToken.ts — Menerbitkan Firebase Auth custom token (dipakai client lewat
 * `signInWithCustomToken(auth, token)`), format sesuai spesifikasi resmi Firebase:
 * https://firebase.google.com/docs/auth/admin/create-custom-tokens#using_a_third-party_jwt_library
 *
 * Ini pengganti server-side dari `firebase-admin`'s `auth().createCustomToken()`,
 * yang TIDAK bisa dipakai di Cloudflare Workers (butuh Node.js runtime). Hasilnya
 * 100% setara — begitu client sign-in dengan token ini, mereka punya sesi Firebase
 * Auth SUNGGUHAN (request.auth di firestore.rules terisi, ID token auto-refresh
 * oleh SDK), bukan lagi token custom yang divalidasi manual lewat `get()` di rules.
 */
import { signRS256 } from './jwt';
import type { ServiceAccount } from './env';

const CUSTOM_TOKEN_AUDIENCE = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';

/**
 * @param uid UID unik untuk user Firebase Auth ini. Dibuat dari role+id supaya tidak
 *   pernah tabrakan antar sekolah/role, mis. "teacher:{schoolId}:{teacherId}".
 * @param claims Custom claims yang akan muncul di request.auth.token pada firestore.rules,
 *   mis. { role: 'teacher', schoolId, teacherId }.
 */
export async function createFirebaseCustomToken(sa: ServiceAccount, uid: string, claims: Record<string, unknown>): Promise<string> {
  if (uid.length > 128) throw new Error('uid custom token melebihi batas 128 karakter Firebase Auth.');
  return signRS256(sa, {
    iss: sa.client_email,
    sub: sa.client_email,
    aud: CUSTOM_TOKEN_AUDIENCE,
    uid,
    claims,
  }, 3600); // Maksimal 1 jam — batas keras dari Firebase, ID token akan auto-refresh oleh client SDK setelahnya.
}

