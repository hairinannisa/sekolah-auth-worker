/**
 * routes/studentLogin.ts — POST /student-login
 * body: { schoolId?, nisn, roomToken, password }
 * respons sukses: { ok: true, customToken, participant, room, schoolId }
 * respons gagal:   { ok: false, reason: 'room_not_found' | 'room_not_active' |
 *                    'participant_not_found' | 'wrong_password' | 'rate_limited' |
 *                    'token_ambiguous' | 'server_error' }
 *
 * Menggantikan verifyParticipantLogin() di cbtSlice.ts. `room` yang dikembalikan
 * berasal dari examRoomsPublic (SUDAH tanpa kunci jawaban, lihat firestore.rules) —
 * aman dikirim langsung ke browser siswa.
 *
 * `schoolId` OPSIONAL: situs sekolah (yang sudah tahu sekolahnya sendiri) tetap boleh
 * kirim schoolId seperti biasa (dipakai langsung, query di-scope ke sekolah itu saja —
 * lebih cepat & tanpa perlu index collection-group). Kalau TIDAK dikirim — dipakai oleh
 * aplikasi CBT "universal" yang cuma minta token, tanpa siswa perlu pilih sekolah dulu —
 * schoolId di-resolve otomatis lewat collection-group query token di examRoomsPublic
 * lintas semua sekolah. Kalau token ternyata kepakai lebih dari satu sekolah sekaligus
 * (harusnya tidak mungkin kalau token dijaga unik nasional saat dibuat, tapi dicek lagi
 * di sini demi keamanan), balas 'token_ambiguous' — jangan asal pilih salah satu sekolah.
 *
 * CATATAN SCOPE: token yang diterbitkan di sini sengaja DIBATASI per-participant
 * (uid = student:{schoolId}:{participantId}), bukan identitas siswa yang persisten
 * lintas ujian — cocok dengan sifat CBT sekarang (satu sesi = satu ruang ujian).
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

  const bodySchoolId = (body.schoolId || '').trim();
  const nisn = (body.nisn || '').trim().replace(/\D/g, '');
  const roomToken = (body.roomToken || '').trim().toUpperCase();
  const password = body.password || '';
  if (!nisn || !roomToken) {
    return jsonResponse({ ok: false, reason: 'bad_request' }, { status: 400, request, env });
  }

  // Sebelum schoolId ter-resolve, pakai roomToken sebagai bucket rate-limit
  // (bukan cuma nisn sendirian) — supaya percobaan tebak-token pun tetap dibatasi.
  const rlKey = `student:${bodySchoolId || roomToken}:${nisn}`;
  const rl = await checkRateLimit(env, rlKey);
  if (!rl.ok) return jsonResponse({ ok: false, reason: 'rate_limited', retryAfterSeconds: rl.retryAfterSeconds }, { status: 429, request, env });

  try {
    const sa = parseServiceAccount(env.FIREBASE_SERVICE_ACCOUNT_JSON);
    const accessToken = await getFirestoreAccessToken(sa);
    const fs = createFirestoreClient(env.FIREBASE_PROJECT_ID, accessToken);

    let schoolId = bodySchoolId;
    let room: Record<string, any> | null;

    if (schoolId) {
      // Sudah tahu sekolahnya (situs per-sekolah) — query di-scope, tidak butuh index collection-group.
      room = await fs.findOneWhere(`sites/${schoolId}/examRoomsPublic`, 'token', roomToken);
    } else {
      // Belum tahu sekolahnya (aplikasi CBT universal) — resolve dari token lintas semua sekolah.
      const found = await fs.findOneWhereCollectionGroup('examRoomsPublic', 'token', roomToken);
      if (found === 'ambiguous') return jsonResponse({ ok: false, reason: 'token_ambiguous' }, { status: 409, request, env });
      if (found === null) return jsonResponse({ ok: false, reason: 'room_not_found' }, { status: 404, request, env });
      schoolId = found.schoolId;
      room = found.data;
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
    return jsonResponse({ ok: true, customToken, participant: { ...participant, id: participantId }, room, schoolId }, { request, env });
  } catch (err: any) {
    console.error('studentLogin error:', err?.message || err);
    return jsonResponse({ ok: false, reason: 'server_error' }, { status: 500, request, env });
  }
}

