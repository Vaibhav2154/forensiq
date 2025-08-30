#!/bin/bash

# Start script for Render deployment
echo "Starting ForensIQ API Server..."
echo "Host: $HOST"
echo "Port: $PORT"

# Use uvicorn directly with environment variables
uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info
