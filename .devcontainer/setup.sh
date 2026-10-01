#!/bin/bash
set -e

echo "============================================"
echo "  Quantaureum V2 - Codespaces Setup"
echo "============================================"

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

echo ""
echo "[1/3] Setting up qaud binary..."
chmod +x qaud
echo "Binary ready: $(./qaud --version 2>/dev/null || echo 'qaud binary OK')"

echo ""
echo "[2/3] Creating data directories..."
mkdir -p data1 data2 data3 logs

echo ""
echo "[3/3] Starting 3-node testnet with tmux..."

if ! command -v tmux &>/dev/null; then
    echo "Installing tmux..."
    sudo apt-get update -qq && sudo apt-get install -y -qq tmux
fi

tmux kill-server 2>/dev/null || true

tmux new-session -d -s node1 -c "$PROJECT_DIR"
tmux send-keys -t node1 "./qaud -config configs/config-codespaces-node1.json 2>&1 | tee logs/node1.log" Enter

sleep 3

tmux new-session -d -s node2 -c "$PROJECT_DIR"
tmux send-keys -t node2 "./qaud -config configs/config-codespaces-node2.json 2>&1 | tee logs/node2.log" Enter

sleep 2

tmux new-session -d -s node3 -c "$PROJECT_DIR"
tmux send-keys -t node3 "./qaud -config configs/config-codespaces-node3.json 2>&1 | tee logs/node3.log" Enter

echo ""
echo "============================================"
echo "  3-Node Testnet is starting!"
echo "============================================"
echo ""
echo "  Node1 RPC:  http://localhost:8545"
echo "  Node2 RPC:  http://localhost:8547"
echo "  Node3 RPC:  http://localhost:8549"
echo ""
echo "  Node1 WS:   http://localhost:8546"
echo "  Node2 WS:   http://localhost:8548"
echo "  Node3 WS:   http://localhost:8550"
echo ""
echo "  tmux sessions: node1, node2, node3"
echo "  Attach:  tmux attach -t node1"
echo "  List:    tmux ls"
echo ""
echo "============================================"
