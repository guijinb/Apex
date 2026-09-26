// Apex 通用工具
// 说明：为了向后兼容，这里保留原有导出名称；
// 但实现已经重写为统一走 _security.js / _response.js / _rateLimit.js。

import {
  constantTimeEqual,
  randomToken,
  generateNumericCode,
  hashIP as _hashIP,
  safeJsonParse,
} from './_security.js';

import { jsonResponse as _jsonResponse, errorResponse, success as _success } from './_response.js';

import { consumeRateLimit } from './_rateLimit.js';

import { consumeToken as _consumeCaptchaToken } from './_captcha.js';

import { getConfig } from './_config.js';

// ---------- 响应 ----------
export function jsonResponse(data, status = 200, requestIdOrExtra = null, maybeExtra = null) {
  let requestId = '';
  let extra = {};
  if (typeof requestIdOrExtra === 'string') {
    requestId = requestIdOrExtra;
    extra = maybeExtra || {};
  } else if (requestIdOrExtra && typeof requestIdOrExtra === 'object') {
    extra = requestIdOrExtra;
  }
  return _jsonResponse(data, status, requestId, extra);
}

export { errorResponse };

// ---------- Token / Code ----------
export function generateToken() {
  return randomToken(32);
}

export function generateCode() {
  return generateNumericCode(6);
}

// ---------- 密码 ----------
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_LEGACY_ITERATIONS = 100000;

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return `v1:${PBKDF2_ITERATIONS}:${toHex(salt)}:${toHex(bits)}`;
}

export async function verifyPassword(password, stored) {
  if (!stored) return false;
  const enc = new TextEncoder();
  let iterations;
  let saltHex;
  let hashHex;

  if (stored.startsWith('v1:')) {
    const parts = stored.split(':');
    if (parts.length !== 4) return false;
    iterations = Number.parseInt(parts[1], 10);
    saltHex = parts[2];
    hashHex = parts[3];
  } else {
    const parts = stored.split(':');
    if (parts.length !== 2) return false;
    iterations = PBKDF2_LEGACY_ITERATIONS;
    saltHex = parts[0];
    hashHex = parts[1];
  }

  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map((b) => Number.parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const newHex = toHex(bits);
  return constantTimeEqual(newHex, hashHex);
}

export function needsRehash(stored) {
  if (!stored) return true;
  if (!stored.startsWith('v1:')) return true;
  const parts = stored.split(':');
  const iterations = Number.parseInt(parts[1], 10);
  return !Number.isFinite(iterations) || iterations < PBKDF2_ITERATIONS;
}

// ---------- 输入清理 ----------
export function sanitize(value, max = 200) {
  if (typeof value !== 'string') return '';
  return value.replace(/[<>"'`;\\]/g, '').trim().substring(0, max);
}

export function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

export function validateUsername(username) {
  return /^[a-zA-Z0-9_]{6,20}$/.test(String(username || '').trim());
}

// ---------- Cookie ----------
export function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const cookies = {};
  header.split(';').forEach((chunk) => {
    const trimmed = chunk.trim();
    if (!trimmed) return;
    const eq = trimmed.indexOf('=');
    if (eq === -1) return;
    const name = trimmed.slice(0, eq);
    const value = trimmed.slice(eq + 1);
    if (name) cookies[name] = value;
  });
  return cookies;
}

export function buildSessionCookie(token, maxAgeSec = 7 * 24 * 60 * 60, env = {}) {
  const config = getConfig(env);
  return `${config.sessionCookie}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`;
}

export function buildClearCookie(env = {}) {
  const config = getConfig(env);
  return `${config.sessionCookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

// ---------- Rate Limit（兼容旧接口，内部走新系统） ----------
export async function checkRateLimit(env, ip, action, maxCount, windowSec) {
  const result = await consumeRateLimit(env, {
    key: `ip:${ip || 'unknown'}`,
    action: String(action),
    max: Number(maxCount),
    windowSec: Number(windowSec),
  });
  return { allowed: Boolean(result.allowed), remaining: result.remaining || 0 };
}

// ---------- CAPTCHA Token 校验（兼容旧接口） ----------
export async function verifyCaptchaTokenV2(env, token, ip, purpose) {
  if (!token) return { valid: false, reason: 'missing_token' };
  const secret = env.CAPTCHA_SECRET;
  if (!secret) return { valid: false, reason: 'no_secret' };
  const ipHash = await _hashIP(ip || '', env.CAPTCHA_SALT || secret);
  // purpose 必须传入，用于绑定 CAPTCHA token 与业务动作（防跨用途重放）
  const result = await _consumeCaptchaToken(env, token, secret, { ipHash, purpose });
  return result;
}

// ---------- 其它工具 ----------
export { _hashIP as hashIP, safeJsonParse };
