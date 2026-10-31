# vsix-admission-demo

Companion to the TestifySec post on the tampered Claude Code extension builds
(2.1.312 and 2.1.313) that Cursor's marketplace served on 29 October 2026. It
rebuilds the attack shape on a toy extension, a real version number on bytes the
publisher never built, and shows `cilock verify` refusing it.

The toy extension is `examplecorp.demo-assistant`. Nothing here is Anthropic's
code, and the "loader" `tamper.py` prepends is one inert line.

## Run

Needs `cilock`, Node.js (for `npx @vscode/vsce`), `openssl`, `git` and Python 3.

```sh
./demo.sh
```

Everything runs offline with throwaway keys in `out/keys/` once vsce is cached.
Every ADMITTED/REFUSED line is the exit code of `cilock verify`.

## What it shows

| Step | Attack | Marketplace gate | Client gate |
|---|---|---|---|
| 3 | none, the real release | admitted | admitted |
| 4 | one file changed, real attestation replayed | refused | refused |
| 5 | attacker attests its own build with its own key | refused | refused |
| 6 | admitted file swapped in storage | refused at download | refused |
| 7 | attacker controls the marketplace and rewrites its policy | admitted | refused |
| 8 | attacker holds the publisher's CI signing key | (not run) | admitted |

The marketplace gate trusts a policy signed by `marketplace.key`. The client
gate trusts a policy signed by `publisher-policy.key`, which the marketplace
never holds. Step 8 is the limit: provenance can't help once the publisher's
build identity is stolen. In real CI, sign keyless with the workflow's OIDC
identity instead of a file key.

VSIX digests change on every run because vsce writes timestamps into the zip.
