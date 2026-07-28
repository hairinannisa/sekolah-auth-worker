/**
 * cors.ts — Header CORS untuk API publik multi-tenant ini. Default: refleksikan
 * origin apa pun yang mengirim request (izinkan semua) karena endpoint ini memang
 * dipanggil dari domain sekolah yang berbeda-beda (subdomain per sekolah) dan tidak
 * memakai cookie (autentikasi lewat body JSON + token di response, bukan sesi
 * cookie) — jadi risiko CSRF/pencurian sesi lewat CORS longgar tidak berlaku di sini.
 * Set ALLOWED_ORIGINS (dipisah koma) di wrangler.toml kalau ingin membatasi.
 */
import type { Env } from './env';

export function corsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get('Origin') || '*';
  const allowList = env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()).filter(Boolean);
  const allowOrigin = !allowList || allowList.length === 0 || allowList.includes(origin) ? origin : allowList[0];
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

export function jsonResponse(body: unknown, init: { status?: number; request: Request; env: Env }): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(init.request, init.env) },
  });
}

