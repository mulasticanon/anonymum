#!/usr/bin/env bash
# Runs a local Anonymum dev chain: builds a chain spec from the compiled
# runtime (dev preset) and starts polkadot-omni-node with 6-second blocks,
# a fresh temporary database, and RPC on 127.0.0.1:9944. Run inside WSL/Linux
# after `get-omni-node.sh`, and after building the runtime on Windows:
#   cargo build --release -p anonymum-runtime   (in substrate/)
#
# omni-node requires relay_chain/para_id in the spec even for a standalone
# dev chain; the values are placeholders and no relay chain is contacted.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
wasm="$here/../target/release/wbuild/anonymum-runtime/anonymum_runtime.compact.compressed.wasm"
cd ~/anonymum-node
cp "$wasm" runtime.wasm
./polkadot-omni-node chain-spec-builder -c chain_spec.json create -t development -c dev -p 1000 \
  -n "Anonymum Dev" -i anonymum_dev --runtime runtime.wasm named-preset development
exec ./polkadot-omni-node --chain chain_spec.json --dev-block-time 6000 --tmp \
  --rpc-port 9944 --rpc-cors all --name anonymum-dev
