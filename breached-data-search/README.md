# Breached Data Search (local threat-intel demo)

This is a local, defensive **breach exposure / threat-intel** demo app.

It does **not** crawl Tor/I2P or private communities. It only queries **configured, lawful sources** (example: HIBP if you add an API key) and returns **metadata-only, redacted** results.

## Run

### 1) Backend

```bash
cd indiatrace/backend
cp .env.example .env
python3 server.py
```

Optional: set `HIBP_API_KEY` in `indiatrace/backend/.env`.

Backend runs on `http://127.0.0.1:8787`.

### 2) Frontend

```bash
cd indiatrace/frontend
python3 -m http.server 5173 --bind 127.0.0.1
```

Open `http://127.0.0.1:5173/index.html`.

## Notes
- Email sending in the UI opens a **mail draft** (mailto) so you can review before sending.
- If `HIBP_API_KEY` is not set, the app will still run but will show **no verified matches** and will list recommended sources.
