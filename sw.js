const CACHE='albverein-schwenningen-v38';
const DATA_CACHE='albverein-schwenningen-data-v1';
const FILES=['./','./index.html','./manifest.webmanifest','./sav-app-icon-192.png','./sav-app-icon-512.png','./sav-app-icon-maskable-512.png','./sav-apple-touch-icon.png','./assets/florian-lessner.jpeg','./assets/matthias-kienitz.jpeg'];
const API_ORIGIN='https://sav-schwenningen-backend.florian-lessner.workers.dev';
const PUSH_API='https://sav-schwenningen-backend.florian-lessner.workers.dev/api/push/latest';
self.addEventListener('install',event=>event.waitUntil((async()=>{await caches.open(CACHE).then(cache=>cache.addAll(FILES));await self.skipWaiting()})()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{const keep=new Set([CACHE,DATA_CACHE]);await caches.keys().then(keys=>Promise.all(keys.filter(key=>!keep.has(key)).map(key=>caches.delete(key))));await clients.claim()})()));
self.addEventListener('fetch',event=>{
  if(event.request.method!=='GET')return;
  const url=new URL(event.request.url);
  if(url.origin===API_ORIGIN&&url.pathname.startsWith('/api/content/')){event.respondWith((async()=>{const cache=await caches.open(DATA_CACHE);try{const response=await fetch(event.request);if(response.ok)await cache.put(event.request,response.clone());return response}catch(error){const cached=await cache.match(event.request);if(cached)return cached;return new Response(JSON.stringify({error:'Offline und noch keine gespeicherten Inhalte verfügbar'}),{status:503,headers:{'content-type':'application/json; charset=utf-8','access-control-allow-origin':'https://app.sav-schwenningen.de','access-control-allow-credentials':'true'}})}})());return}
  if(url.origin!==location.origin)return;
  event.respondWith(caches.match(event.request).then(cached=>cached||fetch(event.request).then(response=>{const copy=response.clone();caches.open(CACHE).then(cache=>cache.put(event.request,copy));return response})));
});
self.addEventListener('push',event=>{
  event.waitUntil((async()=>{
    let message={title:'Neue Meldung vom Albverein',body:'In der App gibt es eine neue Meldung.',url:'https://app.sav-schwenningen.de/#meldungen'};
    try{const response=await fetch(PUSH_API,{cache:'no-store'});if(response.ok)message=await response.json()}catch(error){console.warn('Push-Inhalt konnte nicht geladen werden',error)}
    await self.registration.showNotification(message.title,{body:message.body,icon:'./icon.svg',badge:'./icon.svg',data:{url:message.url},tag:'sav-meldung',renotify:true});
  })());
});
self.addEventListener('notificationclick',event=>{
  event.notification.close();
  event.waitUntil((async()=>{
    const target=event.notification.data?.url||'https://app.sav-schwenningen.de/#meldungen';
    const windows=await clients.matchAll({type:'window',includeUncontrolled:true});
    for(const windowClient of windows){if('navigate'in windowClient)await windowClient.navigate(target);return windowClient.focus()}
    return clients.openWindow(target);
  })());
});
