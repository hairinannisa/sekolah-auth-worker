/**
 * Env — binding yang wajib dikonfigurasi di Cloudflare (lihat README.md untuk
 * cara set masing-masing lewat `wrangler secret put` / wrangler.toml).
 */
export interface Env {
  /** Isi lengkap file JSON service account Firebase (Project Settings → Service
   *  Accounts → Generate new private key), disimpan sebagai SECRET, bukan var biasa. */
  FIREBASE_SERVICE_ACCOUNT_JSON: string;
  /** Project ID Firebase, mis. "studio-9960638705-245ad" (lihat firebase-applet-config.json). */
  FIREBASE_PROJECT_ID: string;
  /** KV namespace untuk rate limiting per-IP/username. Buat dengan:
   *  `wrangler kv:namespace create RATE_LIMIT_KV` lalu tempel id-nya di wrangler.toml. */
  RATE_LIMIT_KV: KVNamespace;
  /** Opsional: daftar origin yang diizinkan CORS, dipisah koma. Kosong = izinkan semua
   *  origin (wajar untuk API publik multi-tenant seperti ini — lihat README.md § CORS). */
  ALLOWED_ORIGINS?: string;
}

export interface ServiceAccount {
  project_id: string;
  private_key: string;
  client_email: string;
}

