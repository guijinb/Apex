// Apex Passkey 前端
// 依赖：window.apiClient（由 src/js/apiClient.js 提供）
(function () {
  'use strict';

  function b64uToBuf(b64u) {
    const s = String(b64u || '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const bin = atob(s + pad);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  function bufToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function detectDeviceName() {
    const ua = navigator.userAgent || '';
    if (/iPhone/.test(ua)) return 'iPhone';
    if (/iPad/.test(ua)) return 'iPad';
    if (/Android/.test(ua)) {
      const m = ua.match(/Android [^;]+;\s*([^)]+)\)/);
      return m ? m[1].trim() : 'Android 设备';
    }
    if (/Macintosh/.test(ua)) return 'Mac';
    if (/Windows/.test(ua)) return 'Windows PC';
    if (/Linux/.test(ua)) return 'Linux PC';
    return '我的设备';
  }

  function isSupported() {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  }

  function friendlyError(e) {
    const name = e && e.name ? e.name : '';
    if (name === 'NotAllowedError') return '操作已取消或超时';
    if (name === 'InvalidStateError') return '该设备已经绑定过了';
    if (name === 'NotSupportedError') return '当前浏览器不支持 Passkey';
    if (name === 'SecurityError') return '需要 HTTPS 环境';
    if (name === 'AbortError') return '操作已中止';
    return (e && e.message) || '操作失败';
  }

  function toast(msg, type) {
    try { if (window.__apex && window.__apex.toast) window.__apex.toast(msg, type || 'error'); }
    catch (e) {}
  }

  // ============ 绑定 ============
  async function register() {
    if (!isSupported()) { toast('当前浏览器不支持 Passkey'); return; }

    const defaultName = detectDeviceName();
    const nameInput = window.prompt('给这个设备起个名字（方便区分）：', defaultName);
    if (nameInput === null) return;
    const deviceName = String(nameInput).trim().substring(0, 40) || defaultName;

    try {
      const res = await window.apiClient.post('/api/passkey/register-challenge', {});
      if (!res || !res.success) { toast((res && res.message) || '获取挑战失败'); return; }

      const pk = res.publicKey;
      const publicKey = {
        challenge: b64uToBuf(pk.challenge),
        rp: pk.rp,
        user: {
          id: new TextEncoder().encode(pk.user.id),
          name: pk.user.name,
          displayName: pk.user.displayName,
        },
        pubKeyCredParams: pk.pubKeyCredParams,
        timeout: pk.timeout || 60000,
        attestation: pk.attestation || 'none',
        authenticatorSelection: pk.authenticatorSelection,
        excludeCredentials: (pk.excludeCredentials || []).map(function (c) {
          return { type: c.type, id: b64uToBuf(c.id), transports: c.transports };
        }),
      };

      const credential = await navigator.credentials.create({ publicKey });
      if (!credential) { toast('绑定已取消'); return; }

      const att = credential.response;
      const payload = {
        challengeId: res.challengeId,
        rawId: bufToB64u(credential.rawId),
        response: {
          clientDataJSON: bufToB64u(att.clientDataJSON),
          attestationObject: bufToB64u(att.attestationObject),
        },
        transports: att.getTransports ? att.getTransports() : [],
        deviceName: deviceName,
      };

      const vr = await window.apiClient.post('/api/passkey/register-verify', payload);
      if (vr && vr.success) {
        toast('Passkey 绑定成功', 'success');
        load();
      } else {
        toast((vr && vr.message) || '绑定失败');
      }
    } catch (e) {
      console.error('[Passkey] register:', e);
      toast('绑定失败：' + friendlyError(e));
    }
  }

  // ============ 登录 ============
  async function login() {
    if (!isSupported()) { toast('当前浏览器不支持 Passkey'); return; }

    const accEl = document.getElementById('login-account');
    const account = accEl ? accEl.value.trim() : '';

    try {
      const res = await window.apiClient.post('/api/passkey/login-challenge', { account: account });
      if (!res || !res.success) { toast((res && res.message) || '获取挑战失败'); return; }

      const pk = res.publicKey;
      const publicKey = {
        challenge: b64uToBuf(pk.challenge),
        rpId: pk.rpId,
        timeout: pk.timeout || 60000,
        userVerification: pk.userVerification || 'preferred',
        allowCredentials: (pk.allowCredentials || []).map(function (c) {
          return { type: c.type, id: b64uToBuf(c.id), transports: c.transports };
        }),
      };

      const assertion = await navigator.credentials.get({ publicKey });
      if (!assertion) { toast('登录已取消'); return; }

      const a = assertion.response;
      const payload = {
        challengeId: res.challengeId,
        rawId: bufToB64u(assertion.rawId),
        response: {
          clientDataJSON: bufToB64u(a.clientDataJSON),
          authenticatorData: bufToB64u(a.authenticatorData),
          signature: bufToB64u(a.signature),
          userHandle: a.userHandle ? bufToB64u(a.userHandle) : null,
        },
      };

      const vr = await window.apiClient.post('/api/passkey/login-verify', payload);
      if (vr && vr.success) {
        toast('登录成功', 'success');
        setTimeout(function () {
          if (window.showHomepage) window.showHomepage(vr.user);
        }, 600);
      } else {
        toast((vr && vr.message) || '登录失败');
      }
    } catch (e) {
      console.error('[Passkey] login:', e);
      toast('登录失败：' + friendlyError(e));
    }
  }

  // ============ 列出 + 删除 ============
  async function load() {
    const listEl = document.getElementById('passkey-list');
    if (!listEl) return;

    try {
      const res = await window.apiClient.get('/api/passkey/list');
      if (!res || !res.success) { listEl.textContent = '无法加载'; return; }

      listEl.replaceChildren();

      if (!res.passkeys || res.passkeys.length === 0) {
        const empty = document.createElement('div');
        empty.style.cssText = 'color:#888;font-size:11px;padding:6px 0;';
        empty.textContent = '尚未绑定任何 Passkey';
        listEl.appendChild(empty);
        return;
      }

      for (const pk of res.passkeys) {
        const item = document.createElement('div');
        item.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#1a1a1a;border-radius:8px;margin-bottom:6px;font-size:11px;';

        const info = document.createElement('div');
        const nameEl = document.createElement('div');
        nameEl.style.cssText = 'font-weight:bold;color:#fff;';
        nameEl.textContent = pk.deviceName || 'Passkey';
        info.appendChild(nameEl);

        const metaEl = document.createElement('div');
        metaEl.style.cssText = 'color:#666;margin-top:2px;font-size:10px;';
        metaEl.textContent = '绑定于 ' + (pk.createdAt ? String(pk.createdAt).slice(0, 10) : '未知');
        info.appendChild(metaEl);

        item.appendChild(info);

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.textContent = '删除';
        delBtn.style.cssText = 'background:transparent;border:1px solid #e63946;color:#e63946;font-size:10px;padding:3px 10px;border-radius:6px;cursor:pointer;';
        delBtn.addEventListener('click', (function (pkId) {
          return async function () {
            if (!window.confirm('确认删除该 Passkey？删除后此设备将无法再用它登录。')) return;
            const dr = await window.apiClient.post('/api/passkey/delete', { credentialId: pkId });
            if (dr && dr.success) { toast('已删除', 'success'); load(); }
            else { toast((dr && dr.message) || '删除失败'); }
          };
        })(pk.id));
        item.appendChild(delBtn);

        listEl.appendChild(item);
      }
    } catch (e) {
      console.error('[Passkey] list:', e);
      listEl.textContent = '加载失败';
    }
  }

  // ============ 导出 + 自动绑定 ============
  window.__apexPasskey = {
    isSupported: isSupported,
    register: register,
    login: login,
    load: load,
  };

  document.addEventListener('DOMContentLoaded', function () {
    if (!isSupported()) {
      const bl = document.getElementById('btn-login-passkey');
      if (bl) bl.style.display = 'none';
      const br = document.getElementById('btn-register-passkey');
      if (br) br.style.display = 'none';
      const wrap = document.getElementById('passkey-login-wrap');
      if (wrap) wrap.style.display = 'none';
      return;
    }

    const bl = document.getElementById('btn-login-passkey');
    if (bl) bl.addEventListener('click', login);

    const br = document.getElementById('btn-register-passkey');
    if (br) br.addEventListener('click', register);
  });

  console.log('[Apex] Passkey 前端已加载');
})();
