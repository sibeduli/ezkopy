#!/bin/bash
# Restart ezkopy container to pick up code changes after git pull
# No rebuild needed unless requirements.txt changes

cd "$(dirname "$0")"

echo "Restarting ezkopy..."
docker compose restart ezkopy
echo "Done! Container restarted."
