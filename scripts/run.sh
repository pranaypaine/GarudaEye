#!/bin/bash
set -e

echo "Building GarudaEye..."
cargo build --bin garudaeye

echo "Starting GarudaEye in local mode..."
./target/debug/garudaeye --mode local --host 0.0.0.0 --port 8000
