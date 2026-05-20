#!/bin/bash
set -e

echo "🏗️  Building release binary with MUSL target..."

# Install MUSL target if not already installed
rustup target add x86_64-unknown-linux-musl || true

# Build for MUSL
echo "📦 Building static binary..."
cargo build --release --target x86_64-unknown-linux-musl

BINARY_PATH="target/x86_64-unknown-linux-musl/release/garudaeye"

# Check if strip is available
if command -v strip &> /dev/null; then
    echo "✂️  Stripping symbols..."
    strip "$BINARY_PATH"
fi

# Show binary size
echo ""
echo "📊 Binary information:"
ls -lh "$BINARY_PATH"
echo ""

# Optional: UPX compression
if command -v upx &> /dev/null; then
    read -p "🗜️  Compress with UPX? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Compressing with UPX..."
        upx --best --lzma "$BINARY_PATH"
        echo ""
        echo "📊 Compressed binary:"
        ls -lh "$BINARY_PATH"
    fi
else
    echo "💡 Tip: Install upx for even smaller binaries: apt-get install upx"
fi

echo ""
echo "✅ Release build complete!"
echo "📍 Binary location: $BINARY_PATH"
