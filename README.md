# TSAROLABS

## Breached Data Search

Local defensive breach exposure / threat-intel demo.

Project lives in `breached-data-search/`.

### Run

Backend:

```bash
cd breached-data-search/backend
cp .env.example .env
python3 server.py
```

Frontend:

```bash
cd breached-data-search/frontend
python3 -m http.server 5173 --bind 127.0.0.1
```

Open `http://127.0.0.1:5173/index.html`.
