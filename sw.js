// Service worker: descifra la guía al vuelo con la clave desenvuelta en el login.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

const MIME = {html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
              js: 'text/javascript; charset=utf-8', json: 'application/json',
              png: 'image/png', jpg: 'image/jpeg', svg: 'image/svg+xml',
              txt: 'text/plain; charset=utf-8', mcstructure: 'application/octet-stream'};

function idb(mode, fn) {
  return new Promise((res, rej) => {
    const r = indexedDB.open('mc-auth', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('keys');
    r.onerror = () => rej(r.error);
    r.onsuccess = () => {
      const tx = r.result.transaction('keys', mode);
      const req = fn(tx.objectStore('keys'));
      tx.oncomplete = () => res(req.result);
      tx.onerror = () => rej(tx.error);
    };
  });
}
const getKey = () => idb('readonly', s => s.get('master')).catch(() => null);
const delKey = () => idb('readwrite', s => s.delete('master'));

const ROOT = new URL('./', self.location.href);

self.addEventListener('fetch', ev => {
  const url = new URL(ev.request.url);
  if (url.origin !== ROOT.origin || !url.pathname.startsWith(ROOT.pathname)) return;
  const rel = url.pathname.slice(ROOT.pathname.length);
  if (rel !== 'app' && !rel.startsWith('app/')) return;  // login y estáticos: red normal
  ev.respondWith(serve(rel));
});

async function serve(rel) {
  if (rel === 'app') return Response.redirect(new URL('app/', ROOT).href, 301);
  if (rel === 'app/logout') { await delKey(); return Response.redirect(ROOT.href, 303); }
  let target = decodeURIComponent(rel.slice(4)) || 'index.html';
  const keyRaw = await getKey();
  if (!keyRaw) return Response.redirect(ROOT.href, 303);
  const resp = await fetch(new URL('enc/' + target, ROOT).href);
  if (!resp.ok) return new Response('No encontrado', {status: 404});
  const buf = new Uint8Array(await resp.arrayBuffer());
  try {
    const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['decrypt']);
    const plain = await crypto.subtle.decrypt({name: 'AES-GCM', iv: buf.subarray(0, 12)}, key, buf.subarray(12));
    const ext = (target.split('.').pop() || '').toLowerCase();
    return new Response(plain, {headers: {'Content-Type': MIME[ext] || 'application/octet-stream',
                                          'Cache-Control': 'no-store',
                                          'X-Robots-Tag': 'noindex, nofollow'}});
  } catch (e) {
    // clave inválida (p. ej. se rotó al borrar un usuario) -> volver al login
    await delKey();
    return Response.redirect(ROOT.href, 303);
  }
}
