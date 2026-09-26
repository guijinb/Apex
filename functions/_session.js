// Session Token 存储：只存 hash，不存明文
// 即使数据库泄露，攻击者也无法还原可用 token

export async function hashSessionToken(token) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode('apex_session_v1_' + token));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}
