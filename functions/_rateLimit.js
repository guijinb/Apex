import { getClientIP, hashIP } from './_security.js';
import { errorResponse } from './_response.js';

export async function consumeRateLimit(env, { key, action, max, windowSec, cost = 1 }) {
  const now = Date.now();
  const windowMs = windowSec * 1000;
  const windowStart = Math.floor(now / windowMs) * windowMs;
  const expiresAt = new Date(windowStart + windowMs + 60 * 1000).toISOString();

  try {
    const row = await env.apex_db.prepare(
      `INSERT INTO rate_limit_buckets (bucket_key, action, window_start, count, expires_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(bucket_key, action, window_start)
       DO UPDATE SET count = count + excluded.count
       RETURNING count`
    ).bind(key, action, windowStart, cost, expiresAt).first();

    const count = Number(row?.count || cost);
    if (count > max) {
      return {
        allowed: false,
        remaining: 0,
        retryAfter: Math.max(1, Math.ceil((windowStart + windowMs - now) / 1000)),
      };
    }
    return { allowed: true, remaining: Math.max(0, max - count) };
  } catch (error) {
    console.error('[RateLimit] consume failed:', error.message);
    return { allowed: false, remaining: 0, error: true };
  }
}

export async function enforceIpRateLimit(env, request, action, max, windowSec, suffix = '') {
  const ip = getClientIP(request);
  const ipHash = await hashIP(ip, env.RATE_LIMIT_SALT || env.CAPTCHA_SECRET || '');
  const key = `ip:${ipHash}${suffix ? ':' + suffix : ''}`;
  const result = await consumeRateLimit(env, { key, action, max, windowSec });
  if (!result.allowed) {
    return errorResponse('请求过于频繁，请稍后再试', 429, 'rate_limited');
  }
  return null;
}

export async function enforceKeyRateLimit(env, action, key, max, windowSec) {
  const result = await consumeRateLimit(env, { key, action, max, windowSec });
  if (!result.allowed) {
    return errorResponse('请求过于频繁，请稍后再试', 429, 'rate_limited');
  }
  return null;
}

export async function cleanupRateLimits(env) {
  try {
    await env.apex_db.prepare('DELETE FROM rate_limit_buckets WHERE expires_at < CURRENT_TIMESTAMP').run();
  } catch (error) {
    console.error('[RateLimit] cleanup failed:', error.message);
  }
}
