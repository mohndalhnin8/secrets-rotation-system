#!/bin/bash
echo "Starting Secrets Rotation System..."
docker-compose up -d
sleep 10
python src/secrets_rotation.py
