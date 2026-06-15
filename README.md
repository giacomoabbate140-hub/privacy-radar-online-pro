# Privacy Radar Online Pro Server

Server proxy per il controllo online Pro.

## Endpoint

- `GET /health`
- `POST /privacy-radar/check`

L'app Android deve usare:

```text
https://TUO-DOMINIO/privacy-radar/check
```

## Variabili ambiente

```text
ONLINE_PRO_TOKEN=token_privato_opzionale
VIRUSTOTAL_API_KEY=chiave_virustotal
SAFE_BROWSING_API_KEY=chiave_google_safe_browsing
PORT=8080
```

Le chiavi API devono stare solo qui sul server, mai nell'APK.

## Deploy rapido su Render

1. Crea un nuovo Web Service.
2. Root directory: `server`.
3. Build command: `npm install`.
4. Start command: `npm start`.
5. Aggiungi le variabili ambiente.
6. Copia l'URL HTTPS generato.
7. Nell'app Privacy Radar inserisci:

```text
https://URL-RENDER/privacy-radar/check
```

## Test locale

```bash
npm start
```

Poi prova:

```bash
curl -X POST http://localhost:8080/privacy-radar/check \
  -H "Content-Type: application/json" \
  -d "{\"packageName\":\"com.android.vending\",\"localScore\":30,\"domains\":[\"google.com\"],\"trackers\":[],\"protectSignals\":[]}"
```
