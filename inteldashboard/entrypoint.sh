#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

echo "Starting Ollama setup script..."

# Install curl (necessary for health checks and model pulling)
echo "Installing curl..."
apt-get update && apt-get install -y curl --no-install-recommends
echo "Curl installed."

# Set environment variables for Ollama host and GPU usage
export OLLAMA_HOST=0.0.0.0 # Configure Ollama to listen on all network interfaces
export OLLAMA_GPU=nvidia # Enable NVIDIA GPU usage for Ollama

# Start Ollama server in the background
# It will now bind to 0.0.0.0 due to OLLAMA_HOST environment variable
ollama serve &
OLLAMA_PID=$! # Store the PID of the background process

echo "Waiting for Ollama server to become responsive..."
# Use 0.0.0.0 for health check as Ollama will now bind to it
until curl -s http://0.0.0.0:11434/api/tags; do
  sleep 5
done
echo "Ollama server is responsive."

# Pull models
echo "Pulling qwen2.5vl:3b..."
ollama pull qwen2.5vl:3b || echo "Failed to pull phi4-reasoning:latest. Continuing..."

echo "Pulling nomic-embed-text:latest..."
ollama pull nomic-embed-text:latest || echo "Failed to pull nomic-embed-text:latest. Continuing..."

echo "Model pulling complete. Handing over to Ollama server."

# Kill the background ollama serve process
kill $OLLAMA_PID

# Start ollama serve in the foreground as the main process (PID 1)
# It will continue to use the OLLAMA_HOST environment variable for binding
exec ollama serve
