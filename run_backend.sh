#!/bin/bash

echo "Starting backend"
cd backend || exit 1
source .env/bin/activate

echo "Activating virtual environment"
cd app
fastapi dev main.py
