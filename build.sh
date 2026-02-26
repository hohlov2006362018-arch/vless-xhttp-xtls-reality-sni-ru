#!/bin/bash
set -euo pipefail

echo "╔══════════════════════════════════════════════╗"
echo "║  Building VPN Parser (Release, optimized)    ║"
echo "╚══════════════════════════════════════════════╝"

# Сборка с максимальной оптимизацией
RUSTFLAGS="-C target-cpu=native -C opt-level=3" \
    cargo build --release 2>&1

# Копируем и переименовываем бинарник
cp target/release/vpn_parser ./vpn_parser.x
chmod +x ./vpn_parser.x

echo ""
echo "✓ Built: vpn_parser.x ($(du -h vpn_parser.x | cut -f1))"
echo "✓ Run:   ./vpn_parser.x"
