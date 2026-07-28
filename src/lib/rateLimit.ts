/**
 * rateLimit.ts — Sliding-window rate limit sederhana pakai Workers KV.
 * Menggantikan rate limit lama yang dicek client-side ke Firestore rateLimits/
 * (gampang dilewati — siapa pun bisa panggil Firestore langsung dari browser dan
 * skip pengecekannya). Sekarang login WAJIB lewat Worker, jadi limiter di sini
 * tidak bisa dilewati sama sekali.
 */
import type { Env } from './env';

const WINDOW_MS = 15 * 60 * 1000; // 15 menit
const MAX_ATTEMPTS = 10;           // 10 percobaan gagal per window per key

export async function checkRateLimit(env: Env, key: string): Promise<{ ok: boolean; retryAfterSeconds?: number }> {
  const kvKey = `ratelimit:${key}`;
  const now = Date.now();
  const raw = await env.RATE_LIMIT_KV.get(kvKey);
  const state = raw ? JSON.parse(raw) as { count: number; windowStart: number } : null;

  if (!state || now - state.windowStart > WINDOW_MS) {
    // Window baru — tidak perlu tulis KV di sini (baru ditulis kalau memang ada
    // percobaan gagal, lihat recordFailedAttempt), supaya login SUKSES tidak
    // menambah latensi dengan write KV yang tidak perlu.
    return { ok: true };
  }
  if (state.count >= MAX_ATTEMPTS) {
    const retryAfterSeconds = Math.ceil((state.windowStart + WINDOW_MS - now) / 1000);
    return { ok: false, retryAfterSeconds };
  }
  return { ok: true };
}

export async function recordFailedAttempt(env: Env, key: string): Promise<void> {
  const kvKey = `ratelimit:${key}`;
  const now = Date.now();
  const raw = await env.RATE_LIMIT_KV.get(kvKey);
  const state = raw ? JSON.parse(raw) as { count: number; windowStart: number } : null;
  const next = (!state || now - state.windowStart > WINDOW_MS)
    ? { count: 1, windowStart: now }
    : { count: state.count + 1, windowStart: state.windowStart };
  await env.RATE_LIMIT_KV.put(kvKey, JSON.stringify(next), { expirationTtl: Math.ceil(WINDOW_MS / 1000) });
}

/** Dipanggil setelah login SUKSES — bersihkan counter supaya user yang sempat typo
 *  password beberapa kali tidak kena limit terus setelah akhirnya berhasil. */
export async function clearRateLimit(env: Env, key: string): Promise<void> {
  await env.RATE_LIMIT_KV.delete(`ratelimit:${key}`).catch(() => {});
}

