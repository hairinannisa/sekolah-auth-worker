/**
 * routes/studentLogin.ts — POST /student-login
 * body: { schoolId?, nisn, roomToken, password }
 * respons sukses: { ok: true, customToken, participant, room }
 * respons gagal:   { ok: false, reason: 'room_not_found' | 'room_not_active' |
 *                    'participant_not_found' | 'wrong_password' | 'rate_limited' |
 *                    'token_ambiguous' | 'server_error' }
 *
 * Menggantikan verifyParticipantLogin() di cbtSlice.ts. `room` yang dikembalikan
 * berasal dari examRoomsPublic (SUDAH tanpa kunci jawaban, lihat firestore.rules) —
 * aman dikirim langsung ke browser siswa.
 *
 * CATATAN SCOPE: token yang diterbitkan di sini sengaja DIBATASI per-participant
 * (uid = student:{schoolId}:{participantId}), bukan identitas siswa yang persisten
 * lintas ujian — cocok dengan sifat CBT sekarang (satu sesi = satu ruang ujian).
 *
 * `schoolId` SEKARANG OPSIONAL — dipertahankan untuk klien yang sudah tahu
 * schoolId-nya sendiri (mis. website sekolah, akses via subdomain) supaya query
 * tetap murah (1 sekolah saja). Kalau tidak dikirim (mis. aplikasi Android — satu
 * APK untuk semua sekolah), schoolId di-resolve otomatis dari `roomToken` lewat
 * collection-group query lintas sekolah — lihat findOneWhereCollectionGroup().
 * Konsekuensinya: roomToken WAJIB unik secara GLOBAL, bukan cuma per-sekolah.
 * Keunikan itu ditegakkan saat guru membuat ruang ujian, lihat routes/checkToken.ts.
 */
import type { Env } from '../lib/env';
import { parseServiceAccount } from '../lib/jwt';
import { getFirestoreAccessToken } from '../lib/googleAuth';
import { createFirestoreClient } from '../lib/firestore';
import { verifyPassword } from '../lib/password';
import { createFirebaseCustomToken } from '../lib/customToken';
import { checkRateLimit, recordFailedAttempt, clearRateLimit } from '../lib/rateLimit';
import { jsonResponse } from '../lib/cors';

interface Body { schoolId?: string; nisn?: string; roomToken?: string; password?: string; }

export async function handleStudentLogin(request: Request, env: Env): Promise<Response> {
  let body: Body;
  try { body = await request.json(); } catch { return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env }); }

  const schoolIdInput = (body.schoolId || '').trim(); // boleh kosong sekarang
  const nisn = (body.nisn || '').trim().replace(/\D/g, '');
  const roomToken = (body.roomToken || '').trim().toUpperCase();
  const password = body.password || '';
  if (!nisn || !roomToken) {
    return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env });
  }

  // Rate limit di-key dari NISN+token (bukan NISN+schoolId) karena schoolId
  // sekarang bisa saja belum diketahui klien sama sekali.
  const rlKey = `student:${roomToken}:${nisn}`;
  const rl = await checkRateLimit(env, rlKey);
  if (!rl.ok) return jsonResponse({ ok: false, reason: 'rate_limited', retryAfterSeconds: rl.retryAfterSeconds }, { status: 429, request, env });

  try {
    const sa = parseServiceAccount(env.FIREBASE_SERVICE_ACCOUNT_JSON);
    const accessToken = await getFirestoreAccessToken(sa);
    const fs = createFirestoreClient(env.FIREBASE_PROJECT_ID, accessToken);

    let schoolId = schoolIdInput;
    let room: Record<string, any> | null = null;

    if (schoolId) {
      // Fast path: klien sudah tahu sekolahnya (mis. website sekolah) — query
      // dibatasi ke satu sekolah saja, lebih murah & lebih cepat.
      room = await fs.findOneWhere(`sites/${schoolId}/examRoomsPublic`, 'token', roomToken);
    } else {
      // Slow path: klien TIDAK tahu schoolId (mis. aplikasi Android multi-sekolah)
      // — cari token ini lintas SEMUA sekolah sekaligus.
      const found = await fs.findOneWhereCollectionGroup('examRoomsPublic', 'token', roomToken);
      if (found === 'ambiguous') {
        // Token yang sama kepakai di >1 sekolah — seharusnya tidak mungkin terjadi
        // kalau checkToken.ts selalu dipakai saat token dibuat, tapi tetap dijaga
        // di sini demi keamanan (jangan pernah asal pilih salah satu).
        return jsonResponse({ ok: false, reason: 'token_ambiguous' }, { status: 409, request, env });
      }
      if (found) {
        schoolId = found.schoolId;
        room = found.data;
      }
    }

    if (!room) return jsonResponse({ ok: false, reason: 'room_not_found' }, { status: 404, request, env });
    if (room.status !== 'active') return jsonResponse({ ok: false, reason: 'room_not_active' }, { status: 403, request, env });

    const participantId = `part_${schoolId}_${room.id}_${nisn}`;
    const participant = await fs.getDoc(`sites/${schoolId}/examParticipants/${participantId}`);
    if (!participant) {
      await recordFailedAttempt(env, rlKey);
      return jsonResponse({ ok: false, reason: 'participant_not_found' }, { status: 404, request, env });
    }

    if (participant.passwordHash) {
      const ok = await verifyPassword(password, participant.passwordHash);
      if (!ok) {
        await recordFailedAttempt(env, rlKey);
        return jsonResponse({ ok: false, reason: 'wrong_password' }, { status: 401, request, env });
      }
    }

    const customToken = await createFirebaseCustomToken(sa, `student:${schoolId}:${participantId}`, {
      role: 'student',
      schoolId,
      roomId: room.id,
      participantId,
    });

    await clearRateLimit(env, rlKey);
    return jsonResponse({ ok: true, customToken, participant: { ...participant, id: participantId, schoolId }, room }, { request, env });
  } catch (err: any) {
    console.error('studentLogin error:', err?.message || err);
    return jsonResponse({ ok: false, reason: 'server_error' }, { status: 500, request, env });
  }
}

