/**
 * routes/checkToken.ts — POST /check-token
 * body: { token }
 * respons: { ok: true, available: boolean }
 *
 * Dipanggil dari panel guru (TeacherCBT.tsx) SEBELUM menyimpan ruang ujian baru,
 * supaya roomToken yang dipakai dijamin unik LINTAS SEKOLAH — wajib, karena sejak
 * studentLogin.ts bisa resolve schoolId dari token secara global (dipakai aplikasi
 * Android yang satu APK untuk semua sekolah), dua sekolah TIDAK BOLEH punya token
 * aktif yang sama; kalau bentrok, studentLogin.ts akan menolak login (lihat reason:
 * 'token_ambiguous') supaya tidak salah mengarahkan siswa ke sekolah yang keliru.
 *
 * Endpoint ini sengaja tidak butuh sesi guru (read-only, cuma balas true/false,
 * tidak membocorkan data apa pun selain "token ini sudah kepakai atau belum" —
 * setara dengan token ujian yang memang akan dipublikasikan ke siswa juga).
 */
import type { Env } from '../lib/env';
import { parseServiceAccount } from '../lib/jwt';
import { getFirestoreAccessToken } from '../lib/googleAuth';
import { createFirestoreClient } from '../lib/firestore';
import { jsonResponse } from '../lib/cors';

interface Body { token?: string; }

export async function handleCheckToken(request: Request, env: Env): Promise<Response> {
  let body: Body;
  try { body = await request.json(); } catch { return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env }); }

  const token = (body.token || '').trim().toUpperCase();
  if (!token) return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env });

  try {
    const sa = parseServiceAccount(env.FIREBASE_SERVICE_ACCOUNT_JSON);
    const accessToken = await getFirestoreAccessToken(sa);
    const fs = createFirestoreClient(env.FIREBASE_PROJECT_ID, accessToken);

    const found = await fs.findOneWhereCollectionGroup('examRoomsPublic', 'token', token);
    const available = found === null;
    return jsonResponse({ ok: true, available }, { request, env });
  } catch (err: any) {
    console.error('checkToken error:', err?.message || err);
    return jsonResponse({ ok: false, reason: 'server_error' }, { status: 500, request, env });
  }
}
