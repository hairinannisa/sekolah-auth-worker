/**
 * routes/parentLogin.ts — POST /parent-login
 * body: { schoolId, nisn, password }
 * respons sukses: { ok: true, customToken, studentId, reportCard }
 * respons gagal:   { ok: false, reason: 'not_found' | 'wrong_password' | 'rate_limited' | 'server_error' }
 *
 * Menggantikan verifyParentLogin() di peopleSlice.ts. Sekalian mengambil
 * studentReportCard di sini (Worker sudah "nyambung" ke Firestore, jadi tidak
 * nambah round-trip terpisah dari sisi client) — client tidak perlu panggil apa pun
 * lagi setelah dapat respons ini selain signInWithCustomToken().
 */
import type { Env } from '../lib/env';
import { parseServiceAccount } from '../lib/jwt';
import { getFirestoreAccessToken } from '../lib/googleAuth';
import { createFirestoreClient } from '../lib/firestore';
import { verifyPassword } from '../lib/password';
import { createFirebaseCustomToken } from '../lib/customToken';
import { checkRateLimit, recordFailedAttempt, clearRateLimit } from '../lib/rateLimit';
import { jsonResponse } from '../lib/cors';

interface Body { schoolId?: string; nisn?: string; password?: string; }

export async function handleParentLogin(request: Request, env: Env): Promise<Response> {
  let body: Body;
  try { body = await request.json(); } catch { return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env }); }

  const schoolId = (body.schoolId || '').trim();
  const nisn = (body.nisn || '').trim().replace(/\D/g, '');
  const password = body.password || '';
  if (!schoolId || !nisn || !password) {
    return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env });
  }

  const rlKey = `parent:${schoolId}:${nisn}`;
  const rl = await checkRateLimit(env, rlKey);
  if (!rl.ok) return jsonResponse({ ok: false, reason: 'rate_limited', retryAfterSeconds: rl.retryAfterSeconds }, { status: 429, request, env });

  try {
    const sa = parseServiceAccount(env.FIREBASE_SERVICE_ACCOUNT_JSON);
    const accessToken = await getFirestoreAccessToken(sa);
    const fs = createFirestoreClient(env.FIREBASE_PROJECT_ID, accessToken);

    const indexDoc = await fs.getDoc(`sites/${schoolId}/parentAuthIndex/${nisn}`);
    if (!indexDoc?.credId) {
      await recordFailedAttempt(env, rlKey);
      return jsonResponse({ ok: false, reason: 'not_found' }, { status: 404, request, env });
    }
    const cred = await fs.getDoc(`sites/${schoolId}/parentAuth/${indexDoc.credId}`);
    if (!cred) {
      await recordFailedAttempt(env, rlKey);
      return jsonResponse({ ok: false, reason: 'not_found' }, { status: 404, request, env });
    }
    if (cred.active === false) {
      return jsonResponse({ ok: false, reason: 'inactive' }, { status: 403, request, env });
    }

    const ok = await verifyPassword(password, cred.passwordHash);
    if (!ok) {
      await recordFailedAttempt(env, rlKey);
      return jsonResponse({ ok: false, reason: 'wrong_password' }, { status: 401, request, env });
    }

    const studentId = cred.studentId as string;
    const [customToken, reportCard] = await Promise.all([
      createFirebaseCustomToken(sa, `parent:${schoolId}:${studentId}`, {
        role: 'parent',
        schoolId,
        studentId,
        nisn,
      }),
      fs.getDoc(`sites/${schoolId}/studentReportCard/${studentId}`),
    ]);

    await clearRateLimit(env, rlKey);
    return jsonResponse({
      ok: true,
      customToken,
      studentId,
      credId: indexDoc.credId,
      credVersion: cred.credVersion ?? 1,
      mustChangePassword: !!cred.mustChangePassword,
      reportCard,
    }, { request, env });
  } catch (err: any) {
    console.error('parentLogin error:', err?.message || err);
    return jsonResponse({ ok: false, reason: 'server_error' }, { status: 500, request, env });
  }
}

