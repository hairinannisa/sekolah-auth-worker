/**
 * password.ts — PORTED 1:1 dari src/core/stores/_utils.ts (hashPassword/verifyPassword).
 *
 * SENGAJA disalin persis, bukan di-refactor jadi shared package, supaya perubahan
 * di satu sisi tidak diam-diam merusak sisi lain — dan supaya jelas: format hash
 * WAJIB tetap "pbkdf2:<iterations>:<saltHex>:<hashHex>" (SHA-256) sama seperti yang
 * sudah tersimpan di jutaan dokumen teacherAuth/parentAuth/examParticipants yang ada.
 * Cloudflare Workers punya WebCrypto (`crypto.subtle`) yang sama persis dengan
 * browser, jadi tidak perlu migrasi hash sama sekali.
 */

function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

async function deriveBits(plain: string, salt: Uint8Array, iterations: number): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(plain), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, 256);
  return bytesToHex(bits);
}

export async function verifyPassword(plain: string, stored: string | undefined | null): Promise<boolean> {
  if (!stored) return false;
  try {
    const [scheme, iterStr, saltHex, hashHex] = stored.split(':');
    if (scheme !== 'pbkdf2' || !saltHex || !hashHex) return false;
    const iterations = parseInt(iterStr, 10);
    const candidateHex = await deriveBits(plain, hexToBytes(saltHex), iterations);
    if (candidateHex.length !== hashHex.length) return false;
    // Perbandingan waktu-konstan (constant-time) — sama seperti versi client.
    let diff = 0;
    for (let i = 0; i < candidateHex.length; i++) diff |= candidateHex.charCodeAt(i) ^ hashHex.charCodeAt(i);
    return diff === 0;
  } catch {
    return false;
  }
}

