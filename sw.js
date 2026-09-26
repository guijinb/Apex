// Apex Service Worker - 离线缓存
// 每次部署前后端不兼容变更时，请手动更新 CACHE_VERSION。
// 变更后浏览器会自动重新安装 SW 并清理旧缓存，
// 避免出现"旧 HTML + 新 API"的兼容性问题。
const CACHE_VERSION = '20260926b';
const CACHE_NAME = 'apex-' + CACHE_VERSION;
const CACHE_URLS = [
  '/',
  '/index.html',
  '/logo.png',
  '/splash-top.webp'
];

// 安装：预缓存核心资源
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(CACHE_URLS))
  );
  self.skipWaiting();
});

// 激活：清理旧缓存
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(names => Promise.all(
      names.filter(n => n !== CACHE_NAME).map(n => caches.delete(n))
    ))
  );
  self.clients.claim();
});

// 拦截请求
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // API 请求直接走网络，不缓存
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // 其他请求：网络优先，失败时回退缓存
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // 成功响应，更新缓存
        if (response.ok && event.request.method === 'GET') {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
