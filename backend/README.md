# Backend der Albverein-App

Dieses Verzeichnis enthält den Cloudflare Worker für die produktive App. Der öffentliche App-Code bleibt auf GitHub Pages; sensible Verarbeitung findet ausschließlich im Worker und in D1 statt.

## Enthalten

- öffentliche, nur lesende Schnittstellen für Termine, Meldungen, Vorstand und Galerie
- geschützte Verwaltungs-Schnittstellen mit individuellen Berechtigungen
- serverseitige Prüfung von Cloudflare-Access-JWTs
- AES-256-GCM-Verschlüsselung für Adress- und Bankänderungen vor der Speicherung
- geschützter Posteingang und Audit-Protokoll
- optionale Turnstile-Prüfung gegen automatisierten Missbrauch
- vorbereiteter, datensparsamer Benachrichtigungs-Webhook ohne Personen- oder Bankdaten

## Noch einzutragen

Vor dem ersten Deployment müssen folgende Platzhalter beziehungsweise Secrets direkt in Cloudflare gesetzt werden:

- D1-Datenbank-ID in `wrangler.jsonc`
- `ACCESS_TEAM_DOMAIN`
- `ACCESS_AUD`
- Secret `DATA_ENCRYPTION_KEY` (32 zufällige Bytes, Base64-kodiert)
- optional `TURNSTILE_SECRET`
- später optional `NOTIFICATION_WEBHOOK_URL` und `NOTIFICATION_WEBHOOK_TOKEN`

Die persönlichen Admin-Adressen und alle Secrets gehören nicht in GitHub. Die Admins werden nach Ausführung der Migration direkt in D1 angelegt.

## Berechtigungen

- `events_manage`
- `notices_manage`
- `board_manage`
- `gallery_manage`
- `changes_view`
- `manage_admins`

Admin 1 erhält alle Berechtigungen. Admin 2 erhält zunächst alle fachlichen Berechtigungen einschließlich `changes_view`, aber nicht `manage_admins`. Admin 3 erhält ausschließlich `changes_view`.

## Lokale Prüfung

```bash
npm install
npm run check
```

Die produktive D1-Datenbank wird erst nach bewusstem Eintragen der Datenbank-ID und der Cloudflare-Secrets verbunden.
