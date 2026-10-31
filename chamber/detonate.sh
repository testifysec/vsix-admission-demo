#!/usr/bin/env bash
# Runs INSIDE the detonation container: no network, throwaway HOME.
# /in (read-only) holds package.vsix and installed/, the package unzipped
# the way an editor installs it. Under cilock's trace, the chamber copies
# both into /work, as an editor downloads and installs an extension, then
# loads extension.js under node, as the editor's extension host does.
# Copying inside the traced command makes package.vsix a product of this
# run, so the signed record is bound to the exact bytes it detonated.
#
# usage: detonate.sh <key> <outfile>
set -euo pipefail
key=$1 out=$2

export HOME=/home/victim DEMO_SANDBOX=1
mkdir -p "$HOME/.ssh" /work

cilock run --step detonate -k "$key" --offline --trace \
  -a environment --workingdir /work -o "$out" -- \
  sh -c 'cp /in/package.vsix /work/ && cp -R /in/installed /work/ &&
    node -e "const ext = require(\"/work/installed/extension/extension.js\"); if (ext.activate) ext.activate(); setTimeout(() => {}, 1500)"'
