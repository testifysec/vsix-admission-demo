#!/usr/bin/env bash
# Marketplace admission demo for VSIX extensions, using cilock.
#
# Keys:
#   publisher          publisher CI signs the build attestation with it
#   publisher-policy   publisher signs the policy its users' editors pin
#   marketplace        marketplace signs its own admission policy
#   attacker           attacker's key; in step 7 the attacker also holds marketplace
#
# Runs offline after the first `npx @vscode/vsce` download. Every decision
# is cilock verify's exit code.
set -uo pipefail
cd "$(dirname "$0")"

VSCE="npx -y @vscode/vsce@3.2.1"
VSIX=demo-assistant-2.1.312.vsix

rm -rf out
mkdir -p out/keys out/publisher out/attacker out/storage

key() {
  openssl ecparam -name prime256v1 -genkey -noout -out "out/keys/$1.key"
  openssl ec -in "out/keys/$1.key" -pubout -out "out/keys/$1.pub" 2>/dev/null
}
for k in publisher publisher-policy marketplace attacker; do key "$k"; done

step() { printf '\n== %s\n' "$*"; }

# gate <label> <signed-policy> <policy-key> <vsix> <bundle>...
gate() {
  local label=$1 policy=$2 pkey=$3 vsix=$4; shift 4
  local args=()
  for b in "$@"; do args+=(-a "$b"); done
  local digest
  digest=$(shasum -a 256 "$vsix" | cut -c1-12)
  if cilock verify "$vsix" -p "$policy" -k "$pkey" "${args[@]}" --offline >out/verify.log 2>&1; then
    printf '%-12s ADMITTED  sha256:%s  %s\n' "$label" "$digest" "$vsix"
  else
    printf '%-12s REFUSED   sha256:%s  %s\n' "$label" "$digest" "$vsix"
    grep -m1 -oE 'Reason: .{0,150}' out/verify.log | sed 's/^/             /'
  fi
}
market() { gate marketplace out/policy.signed.json out/keys/marketplace.pub "$@"; }
client() { gate client out/publisher-policy.signed.json out/keys/publisher-policy.pub "$@"; }

step "1. Publisher CI builds and attests the VSIX"
cp -R extension out/publisher/src
git -C out/publisher/src init -q
git -C out/publisher/src add -A
git -C out/publisher/src -c user.name=publisher -c user.email=ci@example.invalid commit -qm "release 2.1.312"
cilock run --step build -k out/keys/publisher.key --offline \
  --workingdir out/publisher/src -o out/build.bundle.json -- \
  $VSCE package --no-dependencies -o $VSIX >out/build.log 2>&1 \
  || { cat out/build.log; exit 1; }
mv out/publisher/src/$VSIX out/publisher/$VSIX
echo "built        sha256:$(shasum -a 256 out/publisher/$VSIX | cut -c1-12)  out/publisher/$VSIX"

step "2. Policies: one signed by the marketplace, one signed by the publisher"
# Demo shortcut: derive the policy from the first bundle. It names one step,
# "build", whose attestation must be signed by publisher.pub.
cilock policy from-bundles -k out/keys/publisher.pub -o out/policy.json out/build.bundle.json >/dev/null 2>&1
cilock sign -k out/keys/marketplace.key -f out/policy.json -o out/policy.signed.json --offline >/dev/null 2>&1
cilock sign -k out/keys/publisher-policy.key -f out/policy.json -o out/publisher-policy.signed.json --offline >/dev/null 2>&1
echo "policy       step=build  functionary=publisher.pub"

step "3. The real release"
market out/publisher/$VSIX out/build.bundle.json
client out/publisher/$VSIX out/build.bundle.json

step "4. One file changed, same name, version and manifest; real attestation replayed"
python3 -I tamper.py out/publisher/$VSIX out/attacker/$VSIX
market out/attacker/$VSIX out/build.bundle.json
client out/attacker/$VSIX out/build.bundle.json

step "5. Attacker attests its own build with its own key"
git -C out/attacker init -q
git -C out/attacker -c user.name=attacker -c user.email=a@example.invalid commit -q --allow-empty -m "release 2.1.313"
cilock run --step build -k out/keys/attacker.key --offline \
  --workingdir out/attacker -o out/attacker.bundle.json -- \
  python3 -I ../../tamper.py ../publisher/$VSIX rebuilt.vsix >out/attacker-build.log 2>&1
market out/attacker/rebuilt.vsix out/build.bundle.json out/attacker.bundle.json
client out/attacker/rebuilt.vsix out/build.bundle.json out/attacker.bundle.json

step "6. Admitted file swapped in storage; the gate runs again before download"
cp out/publisher/$VSIX out/storage/$VSIX
market out/storage/$VSIX out/build.bundle.json
cp out/attacker/$VSIX out/storage/$VSIX
market out/storage/$VSIX out/build.bundle.json
client out/storage/$VSIX out/build.bundle.json

step "7. Attacker controls the marketplace and rewrites its policy"
cilock policy from-bundles -k out/keys/attacker.pub -o out/attacker-policy.json out/attacker.bundle.json >/dev/null 2>&1
cilock sign -k out/keys/marketplace.key -f out/attacker-policy.json -o out/policy.signed.json --offline >/dev/null 2>&1
market out/attacker/rebuilt.vsix out/attacker.bundle.json
client out/attacker/rebuilt.vsix out/attacker.bundle.json

step "8. Limit: attacker holds the publisher's CI signing key"
cilock run --step build -k out/keys/publisher.key --offline \
  --workingdir out/attacker -o out/stolen.bundle.json -- \
  python3 -I ../../tamper.py ../publisher/$VSIX stolen-key.vsix >out/stolen-build.log 2>&1
client out/attacker/stolen-key.vsix out/stolen.bundle.json
