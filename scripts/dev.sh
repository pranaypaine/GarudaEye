#!/bin/bash
set -e

echo "🚀 Starting GarudaEye in development mode..."

# Create data directory
mkdir -p data

# Copy example env if .env doesn't exist
if [ ! -f .env ]; then
    echo "📋 Creating .env from .env.example"
    cp .env.example .env
fi

# Run with cargo watch if available, otherwise just cargo run
if command -v cargo-watch &> /dev/null; then
    echo "👀 Using cargo-watch for hot reload"
    cargo watch -x 'run -- --mode local --open'
else
    echo "💡 Tip: Install cargo-watch for hot reload: cargo install cargo-watch"
    cargo run -- --mode local --open
fi
