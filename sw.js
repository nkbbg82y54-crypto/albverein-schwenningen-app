const CACHE='albverein-schwenningen-v22';
const FILES=['./','./index.html','./manifest.webmanifest','./icon.svg','./assets/florian-lessner.jpeg','./assets/matthias-kienitz.jpeg'];
const PUSH_API='https://sav-schwenningen-backend.florian-lessner.workers.dev/api/push/latest';
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(FILES))));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key!==CACHE).map(key=>caches.delete(key))))));
self.addEventListener('fetch',event=>{
  if(event.request.method!=='GET'||new URL(event.request.url).origin!==location.origin)return;
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
