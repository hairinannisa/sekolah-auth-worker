/**
 * firestore.ts — Klien REST API Firestore MINIMAL, cuma untuk BACA (getDoc + query
 * "where field == value" 1 hasil). Worker login TIDAK PERNAH perlu menulis apa pun
 * ke Firestore — begitu client sign-in dengan custom token, Firebase Auth SDK yang
 * mengurus persistensi sesi (tidak perlu lagi dokumen teacherSessions/parentActiveSessions
 * seperti pola lama). Dipakai dengan access token dari googleAuth.ts (privilese admin,
 * bypass firestore.rules — makanya file ini TIDAK PERNAH dipakai dari client/browser).
 */

const BASE = 'https://firestore.googleapis.com/v1';

// ── Decoder: Firestore REST "Value" JSON → plain JS ─────────────────────────────
// (Cuma tipe yang benar-benar dipakai skema kredensial/sesi di app ini.)
function decodeValue(v: any): any {
  if (v == null) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return parseInt(v.integerValue, 10);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('timestampValue' in v) return v.timestampValue;
  if ('mapValue' in v) return decodeFields(v.mapValue.fields || {});
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(decodeValue);
  return null;
}

function decodeFields(fields: Record<string, any>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(fields)) out[k] = decodeValue(v);
  return out;
}

export interface FirestoreClient {
  /** Ambil satu dokumen by path lengkap (mis. "teacherAuthIndex/budi123"). null kalau tidak ada. */
  getDoc(path: string): Promise<Record<string, any> | null>;
  /** Cari SATU dokumen di sebuah collection dengan field == value. null kalau tidak ada. */
  findOneWhere(collectionPath: string, field: string, value: string): Promise<Record<string, any> | null>;
}

export function createFirestoreClient(projectId: string, accessToken: string): FirestoreClient {
  const documentsRoot = `${BASE}/projects/${projectId}/databases/(default)/documents`;
  const headers = { Authorization: `Bearer ${accessToken}` };

  return {
    async getDoc(path: string) {
      const res = await fetch(`${documentsRoot}/${path}`, { headers });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`Firestore getDoc(${path}) gagal: ${res.status} ${await res.text().catch(() => '')}`);
      const data = await res.json() as { fields?: Record<string, any> };
      return decodeFields(data.fields || {});
    },

    async findOneWhere(collectionPath: string, field: string, value: string) {
      // collectionPath boleh nested, mis. "sites/{schoolId}/examRoomsPublic" — runQuery
      // dijalankan relatif ke parent dari collection tsb.
      const lastSlash = collectionPath.lastIndexOf('/');
      const parent = lastSlash === -1 ? '' : collectionPath.slice(0, lastSlash);
      const collectionId = lastSlash === -1 ? collectionPath : collectionPath.slice(lastSlash + 1);
      const url = `${documentsRoot}${parent ? '/' + parent : ''}:runQuery`;
      const res = await fetch(url, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          structuredQuery: {
            from: [{ collectionId }],
            where: {
              fieldFilter: {
                field: { fieldPath: field },
                op: 'EQUAL',
                value: { stringValue: value },
              },
            },
            limit: 1,
          },
        }),
      });
      if (!res.ok) throw new Error(`Firestore findOneWhere(${collectionPath}) gagal: ${res.status} ${await res.text().catch(() => '')}`);
      const rows = await res.json() as Array<{ document?: { fields?: Record<string, any> } }>;
      const doc = rows.find(r => r.document)?.document;
      return doc ? decodeFields(doc.fields || {}) : null;
    },
  };
}

