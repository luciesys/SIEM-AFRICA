// ================================================================
//  SIEM Africa — Service Worker v2.0
//  Cache offline + Polling arriere-plan
// ================================================================
'use strict';

const CACHE    = 'siem-africa-v2';
const ASSETS   = ['/mobile/', '/mobile/style.css', '/mobile/app.js', '/mobile/manifest.json'];

self.addEventListener('install', e => {
    e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS).catch(() => {})));
    self.skipWaiting();
});

self.addEventListener('activate', e => {
    e.waitUntil(caches.keys().then(keys =>
        Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ));
    self.clients.claim();
    startPolling();
});

self.addEventListener('fetch', e => {
    if (e.request.url.includes('/api/') || e.request.url.includes('/login') ||
        e.request.url.includes('/logout') || e.request.method !== 'GET') {
        e.respondWith(fetch(e.request).catch(() =>
            new Response(JSON.stringify({ error: 'offline' }),
                         { headers: { 'Content-Type': 'application/json' } })
        ));
        return;
    }
    e.respondWith(
        caches.match(e.request).then(cached =>
            cached || fetch(e.request).then(res => {
                if (res.ok) {
                    caches.open(CACHE).then(c => c.put(e.request, res.clone()));
                }
                return res;
            }).catch(() => cached || new Response('Offline', { status: 503 }))
        )
    );
});

// ── Notifications push ────────────────────────────────────────────
self.addEventListener('push', e => {
    let data = { title: 'SIEM Africa', body: 'Nouvelle alerte', gravite: 2 };
    if (e.data) { try { data = e.data.json(); } catch { data.body = e.data.text(); } }

    e.waitUntil(self.registration.showNotification(data.title, {
        body:     data.body,
        icon:     '/mobile/icon-192.png',
        badge:    '/mobile/icon-192.png',
        vibrate:  data.gravite >= 3 ? [200, 100, 200, 100, 400] : [100],
        tag:      `siem-${data.alerte_id || Date.now()}`,
        renotify: true,
        requireInteraction: data.gravite === 4,
        data:     { alerte_id: data.alerte_id, gravite: data.gravite },
        actions:  data.gravite >= 3 ? [
            { action: 'voir',    title: '👁 Voir' },
            { action: 'bloquer', title: '🚫 Bloquer' },
        ] : [{ action: 'voir', title: '👁 Voir' }]
    }));
});

self.addEventListener('notificationclick', e => {
    e.notification.close();
    const url = e.action === 'bloquer'
        ? `/mobile/#alerte-${e.notification.data?.alerte_id}`
        : '/mobile/';
    e.waitUntil(
        self.clients.matchAll({ type: 'window' }).then(clients => {
            const existing = clients.find(c => c.url.includes('/mobile'));
            return existing ? existing.focus() : self.clients.openWindow(url);
        })
    );
});

// ── Polling arriere-plan ──────────────────────────────────────────
let lastId = null;

function startPolling() {
    setInterval(checkAlertes, 30000);
}

async function checkAlertes() {
    try {
        const res = await fetch('/api/alertes/', { credentials: 'include' });
        if (!res.ok) return;
        const data    = await res.json();
        const alertes = data.alertes || [];
        if (!alertes.length) return;
        const first   = alertes[0];
        if (first.id === lastId || first.gravite < 3) return;
        lastId = first.id;

        const clients = await self.clients.matchAll({ type: 'window' });
        if (clients.some(c => c.visibilityState === 'visible')) return;

        const gravLabel = { 4: '🚨 CRITIQUE', 3: '⚠️ HAUTE' };
        await self.registration.showNotification(
            `SIEM Africa — ${gravLabel[first.gravite] || 'Alerte'}`, {
                body:    `${first.nom_attaque} — IP: ${first.ip_source || 'N/A'} (${first.pays_source || '?'})`,
                icon:    '/mobile/icon-192.png',
                vibrate: first.gravite === 4 ? [200,100,200,100,400] : [100],
                tag:     `siem-bg-${first.id}`,
                requireInteraction: first.gravite === 4,
                data:    { alerte_id: first.id, gravite: first.gravite },
                actions: [
                    { action: 'voir',    title: '👁 Voir' },
                    { action: 'bloquer', title: '🚫 Bloquer' }
                ]
            }
        );
    } catch (e) { /* silencieux */ }
}
