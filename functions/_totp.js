// TOTP (RFC 6238) 实现 - 纯 JS 无依赖

function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  str = str.replace(/=+$/, '').toUpperCase();
  let bits = '';
  for (const c of str) {
    const val = alphabet.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let result = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    result += alphabet[parseInt(bits.substring(i, i + 5), 2)];
  }
  return result;
}

async function generateTotp(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 30000);
  const key = base32Decode(secret);
  const counterBytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) { counterBytes[i] = c & 0xff; c = Math.floor(c / 256); }
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, counterBytes);
  const bytes = new Uint8Array(sig);
  const offset = bytes[bytes.length - 1] & 0x0f;
  const code = ((bytes[offset] & 0x7f) << 24) |
               ((bytes[offset + 1] & 0xff) << 16) |
               ((bytes[offset + 2] & 0xff) << 8) |
               (bytes[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

export async function verifyTotp(secret, code) {
  if (!secret || !code || code.length !== 6) return false;
  const now = Date.now();
  for (const offset of [-30000, 0, 30000]) {
    const expected = await generateTotp(secret, now + offset);
    if (expected === code) return true;
  }
  return false;
}

export function generateTotpSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return base32Encode(bytes);
}

export function buildOtpauthUrl(secret, accountName, issuer = 'Apex Admin') {
  return 'otpauth://totp/' + encodeURIComponent(issuer) + ':' + encodeURIComponent(accountName) +
    '?secret=' + secret + '&issuer=' + encodeURIComponent(issuer);
}
