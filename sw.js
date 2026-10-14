const CACHE='albverein-schwenningen-v47';
const DATA_CACHE='albverein-schwenningen-data-v1';
const APP_ROOT='https://app.sav-schwenningen.de/';
const APP_SHELL='https://app.sav-schwenningen.de/index.html';
const FILES=['./manifest.webmanifest','./sav-app-icon-192.png','./sav-app-icon-512.png','./sav-app-icon-maskable-512.png','./sav-apple-touch-icon.png','./assets/startseite-donautal.jpg','./assets/florian-lessner.jpeg','./assets/matthias-kienitz.jpeg'];
const API_ORIGIN='https://sav-schwenningen-backend.florian-lessner.workers.dev';
const PUSH_API='https://sav-schwenningen-backend.florian-lessner.workers.dev/api/push/latest';
self.addEventListener('install',event=>event.waitUntil((async()=>{const cache=await caches.open(CACHE),shell=await fetch(APP_SHELL,{cache:'reload'});if(!shell.ok)throw new Error('App shell could not be cached');await cache.put(APP_ROOT,shell.clone());await cache.put(APP_SHELL,shell.clone());await cache.addAll(FILES);await self.skipWaiting()})()));
self.addEventListener('activate',event=>event.waitUntil((async()=>{const keep=new Set([CACHE,DATA_CACHE]);await caches.keys().then(keys=>Promise.all(keys.filter(key=>!keep.has(key)).map(key=>caches.delete(key))));await clients.claim()})()));
self.addEventListener('fetch',event=>{
  if(event.request.method!=='GET')return;
  const url=new URL(event.request.url);
  if(url.origin===API_ORIGIN&&url.pathname.startsWith('/api/content/')){event.respondWith((async()=>{const forceFresh=url.searchParams.has('savRefresh');url.searchParams.delete('savRefresh');const canonicalUrl=url.href,cache=await caches.open(DATA_CACHE),cached=await cache.match(canonicalUrl);const update=async()=>{const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),3500);try{const response=await fetch(event.request,{signal:controller.signal});if(response.ok)await cache.put(canonicalUrl,response.clone());return response}finally{clearTimeout(timer)}};if(cached&&!forceFresh){event.waitUntil(update().catch(error=>console.warn('Inhalte konnten nicht aktualisiert werden',error)));return cached}try{return await update()}catch(error){if(cached)return cached;return new Response(JSON.stringify({error:'Offline und noch keine gespeicherten Inhalte verfügbar'}),{status:503,headers:{'content-type':'application/json; charset=utf-8','access-control-allow-origin':'https://app.sav-schwenningen.de','access-control-allow-credentials':'true'}})}})());return}
  if(url.origin!==location.origin)return;
  if(event.request.mode==='navigate'){event.respondWith((async()=>{const cache=await caches.open(CACHE),cached=await cache.match(APP_ROOT)||await cache.match(APP_SHELL);const update=async()=>{const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),3500);try{const response=await fetch(event.request,{cache:'no-store',signal:controller.signal});if(response.ok){await cache.put(APP_ROOT,response.clone());await cache.put(APP_SHELL,response.clone())}return response}finally{clearTimeout(timer)}};if(cached){event.waitUntil(update().catch(error=>console.warn('Startseite konnte nicht aktualisiert werden',error)));return cached}try{return await update()}catch(error){return new Response('<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#315b38"><title>Albverein – Offline</title><body style="margin:0;background:#f7f5ee;color:#1d2a22;font:17px -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif"><main style="max-width:520px;margin:18vh auto;padding:28px"><h1 style="font-family:Georgia,serif;color:#315b38">Albverein Schwenningen/Heuberg</h1><p>Die App ist gerade offline und es sind noch keine Inhalte gespeichert.</p><p>Bitte stelle einmal kurz eine Internetverbindung her und öffne die App erneut.</p></main></body></html>',{headers:{'content-type':'text/html; charset=utf-8'}})}})());return}
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
