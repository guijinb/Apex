// Apex Service Worker — 自杀/注销版
//
// 说明：旧版 SW 会缓存 HTML 导致用户看到过期内容。
// 本版本负责：
//   1. 清空所有缓存
//   2. 注销自己（unregister）
//   3. 通知所有客户端重新加载
//
// 一旦所有用户设备升级到此版本，Apex 将不再使用 Service Worker。

self.addEventListener('install', function (event) {
  // 立即激活，不等待旧版本
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    (async function () {
      // 1) 清空所有缓存
      try {
        const keys = await caches.keys();
        await Promise.all(keys.map(function (k) { return caches.delete(k); }));
      } catch (e) {}

      // 2) 注销自己
      try {
        await self.registration.unregister();
      } catch (e) {}

      // 3) 通知所有客户端重新加载（让用户看到最新 HTML）
      try {
        const clients = await self.clients.matchAll({ type: 'window' });
        clients.forEach(function (c) {
          try { c.navigate(c.url); } catch (e) {}
        });
      } catch (e) {}
    })()
  );
});

// fetch 直接走网络（不做任何缓存）
self.addEventListener('fetch', function () {
  // 不调用 respondWith → 走浏览器默认行为
});
