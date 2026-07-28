/**
 * index.ts — Router utama Worker. 3 endpoint login + OPTIONS (CORS preflight).
 */
import type { Env } from './lib/env';
import { corsHeaders } from './lib/cors';
import { handleTeacherLogin } from './routes/teacherLogin';
import { handleParentLogin } from './routes/parentLogin';
import { handleStudentLogin } from './routes/studentLogin';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: corsHeaders(request, env) });
    }

    switch (url.pathname) {
      case '/teacher-login':
        return handleTeacherLogin(request, env);
      case '/parent-login':
        return handleParentLogin(request, env);
      case '/student-login':
        return handleStudentLogin(request, env);
      default:
        return new Response('Not Found', { status: 404, headers: corsHeaders(request, env) });
    }
  },
};

