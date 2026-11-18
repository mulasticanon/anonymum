#!/usr/bin/env bash
# Downloads the official polkadot-omni-node (Linux x86_64) from the Polkadot
# SDK release this runtime is built against, into ~/anonymum-node, and checks
# its SHA-256 against the release's published checksum. Run inside WSL/Linux.
# The checksum comes from the same release page; the GPG signature (.asc) is
# not checked here.
set -euo pipefail
release=polkadot-stable2609-2
mkdir -p ~/anonymum-node && cd ~/anonymum-node
base="https://github.com/paritytech/polkadot-sdk/releases/download/$release"
curl -sSfL -o polkadot-omni-node "$base/polkadot-omni-node"
curl -sSfL -o polkadot-omni-node.sha256 "$base/polkadot-omni-node.sha256"
sha256sum -c polkadot-omni-node.sha256
chmod +x polkadot-omni-node
./polkadot-omni-node --version
