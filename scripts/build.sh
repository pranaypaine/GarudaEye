#!/bin/bash
set -e

echo "🔨 Building GarudaEye..."

# Build the project
cargo build --release

echo "✅ Build complete!"
echo "Binary location: target/release/garudaeye"
