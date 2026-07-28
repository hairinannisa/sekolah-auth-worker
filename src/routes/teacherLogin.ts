/**
 * routes/teacherLogin.ts — POST /teacher-login
 * body: { schoolId, username, password }
 * respons sukses: { ok: true, customToken, teacherId }
 * respons gagal:   { ok: false, reason: 'not_found' | 'wrong_password' | 'rate_limited' | 'server_error' }
 *
 * Menggantikan verifyTeacherLogin() di src/core/stores/peopleSlice.ts (client-side).
 * Bedanya: di sini kita MEMEGANG service account (privilese admin, bypass rules),
 * jadi tidak perlu 2 getDoc bolak-balik dari BROWSER (index → cred) yang tiap
 * round-trip-nya kena latensi jaringan pengguna — semua lookup di sini terjadi di
 * jaringan internal Google/Cloudflare yang jauh lebih cepat, dan client cuma perlu
 * SATU request ke Worker ini.
 */
import type { Env } from '../lib/env';
import { parseServiceAccount } from '../lib/jwt';
import { getFirestoreAccessToken } from '../lib/googleAuth';
import { createFirestoreClient } from '../lib/firestore';
import { verifyPassword } from '../lib/password';
import { createFirebaseCustomToken } from '../lib/customToken';
import { checkRateLimit, recordFailedAttempt, clearRateLimit } from '../lib/rateLimit';
import { jsonResponse } from '../lib/cors';

interface Body { schoolId?: string; username?: string; password?: string; }

export async function handleTeacherLogin(request: Request, env: Env): Promise<Response> {
  let body: Body;
  try { body = await request.json(); } catch { return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env }); }

  const schoolId = (body.schoolId || '').trim();
  const username = (body.username || '').trim().toLowerCase();
  const password = body.password || '';
  if (!schoolId || !username || !password) {
    return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env });
  }

  const rlKey = `teacher:${schoolId}:${username}`;
  const rl = await checkRateLimit(env, rlKey);
  if (!rl.ok) return jsonResponse({ ok: false, reason: 'rate_limited', retryAfterSeconds: rl.retryAfterSeconds }, { status: 429, request, env });

  try {
    const sa = parseServiceAccount(env.FIREBASE_SERVICE_ACCOUNT_JSON);
    const accessToken = await getFirestoreAccessToken(sa);
    const fs = createFirestoreClient(env.FIREBASE_PROJECT_ID, accessToken);

    // 1. username → credId lewat index (skema modern, UUID doc id)
    let cred: Record<string, any> | null = null;
    const indexDoc = await fs.getDoc(`sites/${schoolId}/teacherAuthIndex/${username}`);
    if (indexDoc?.credId) {
      cred = await fs.getDoc(`sites/${schoolId}/teacherAuth/${indexDoc.credId}`);
    } else {
      // Fallback skema lama (sebelum migrasi UUID): doc id = username langsung.
      // Worker ini TIDAK menulis migrasi otomatis (read-only by design) — cukup
      // biarkan login tetap berhasil; migrasi tetap bisa terjadi lewat jalur lama
      // di client kalau suatu saat dipanggil, atau dirapikan manual oleh admin.
      cred = await fs.getDoc(`sites/${schoolId}/teacherAuth/${username}`);
    }

    if (!cred) {
      await recordFailedAttempt(env, rlKey);
      return jsonResponse({ ok: false, reason: 'not_found' }, { status: 404, request, env });
    }

    const ok = await verifyPassword(password, cred.passwordHash);
    if (!ok) {
      await recordFailedAttempt(env, rlKey);
      return jsonResponse({ ok: false, reason: 'wrong_password' }, { status: 401, request, env });
    }

    const teacherId = cred.teacherId as string;
    const customToken = await createFirebaseCustomToken(sa, `teacher:${schoolId}:${teacherId}`, {
      role: 'teacher',
      schoolId,
      teacherId,
    });

    await clearRateLimit(env, rlKey);
    return jsonResponse({ ok: true, customToken, teacherId }, { request, env });
  } catch (err: any) {
    console.error('teacherLogin error:', err?.message || err);
    return jsonResponse({ ok: false, reason: 'server_error' }, { status: 500, request, env });
  }
}

