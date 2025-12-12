# ezkopy

Clipboard bridge for VPS terminals.

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

**Web UI:** `http://<host>:5000`

**Terminal:**
```bash
# Get clipboard
curl http://<host>:5000/raw

# Set clipboard
curl -X POST -d "your text" http://<host>:5000/raw

# Pipe file
cat file.txt | curl -X POST --data-binary @- http://<host>:5000/raw
```
