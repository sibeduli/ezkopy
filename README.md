# ezkopy

Clipboard bridge for VPS terminals with user authentication.

## Features

- **Per-user clipboards** - each user has their own private clipboard
- **Web UI** - login, manage clipboard, configure settings
- **Terminal access** - via PIN or IP whitelist
- **Admin panel** - user management and logs

## Setup (venv)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Docker

```bash
docker compose up -d
```

## Usage

### Web UI

1. Open `http://<host>:5000`
2. Register (first user becomes admin)
3. Login and configure PIN or IP whitelist in Settings

### Terminal

**With PIN:**
```bash
curl http://<host>:5000/u/<username>/<pin>/raw
curl -X POST -d "text" http://<host>:5000/u/<username>/<pin>/raw
cat file.txt | curl -X POST --data-binary @- http://<host>:5000/u/<username>/<pin>/raw
```

**With whitelisted IP (no PIN needed):**
```bash
curl http://<host>:5000/u/<username>/raw
curl -X POST -d "text" http://<host>:5000/u/<username>/raw
```

## Environment Variables

- `SECRET_KEY` - Flask secret key (auto-generated if not set)
- `EZKOPY_DB` - Database path (default: `clipboard.db`)
