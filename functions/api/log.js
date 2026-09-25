import { sanitize, jsonResponse } from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const body = await request.json();
    const type = sanitize(body.type || 'unknown').substring(0, 20);
    const message = sanitize(body.message || '').substring(0, 500);
    const url = sanitize(body.url || '').substring(0, 300);
    const ua = (request.headers.get('User-Agent') || '').substring(0, 200);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    await env.apex_db.prepare(
      'INSERT INTO logs (type, message, url, user_agent, ip) VALUES (?, ?, ?, ?, ?)'
    ).bind(type, message, url, ua, ip).run();

    return jsonResponse({ success: true });
  } catch (err) {
    return jsonResponse({ success: false }, 200);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
