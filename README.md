# vsix-admission-demo

Companion to the TestifySec post on the tampered Claude Code extension builds
(2.1.312 and 2.1.313) that Cursor's marketplace served on 29 October 2026. It
rebuilds the attack shape on a toy extension, a real version number on bytes the
publisher never built, and shows `cilock verify` refusing it.

The toy extension is `examplecorp.demo-assistant`. Nothing here is Anthropic's
code, and the "loader" `tamper.py` prepends is one inert line.

## Run

Needs `cilock`, Node.js (for `npx @vscode/vsce`), `openssl`, `git` and Python 3.
Step 9 also needs Docker; it downloads the matching Linux cilock from the
TestifySec platform's tools endpoint.

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
| 9 | same stolen-key package, loaded in the detonation chamber | refused: wrote `~/.ssh/authorized_keys`, connected out | |
| 10 | publisher ships its own detonation; user checks build + detonation | | real release admitted; stolen build key refused (no detonation); stolen build and chamber keys refused (the trace shows the SSH write) |

The marketplace gate trusts a policy signed by `marketplace.key`. The client
gate trusts a policy signed by `publisher-policy.key`, which the marketplace
never holds. Step 8 is the limit: provenance can't help once the publisher's
build identity is stolen. In real CI, sign keyless with the workflow's OIDC
identity instead of a file key.

## The detonation chamber (step 9)

`chamber/detonate.sh` runs in a `node:22` container with `--network none`
and a throwaway `HOME`. Under `cilock run --trace` it copies the package in,
unzips it as an editor installs it, and loads `extension.js` under Node, as
the extension host does. cilock records every process, file write and
connection, signs the record with the chamber key, and binds it to the VSIX
digest. `chamber/detonation.rego` refuses a load that writes or opens
anything under `.ssh/`, `LaunchAgents/` or the cron spool, connects to a
non-loopback address, or recorded no processes at all.

The toy loader in `tamper.py` writes a fake key (not a valid key) and
connects to 192.0.2.1, a documentation address. It only acts when
`DEMO_SANDBOX=1`, which only the chamber sets.

Step 10 has the publisher run the same chamber in its own CI under a
second identity (`publisher-chamber`) and ship the signed trace with the
release. The publisher's policy requires both the `build` and `detonate`
steps, so a user can check both before installing. The rego runs at verify
time: a validly signed trace that shows the SSH write still fails.

Limits: malware that detects the sandbox, waits, or needs a user action can
load clean. The trace runs in ptrace mode inside Docker, which cilock marks
as partial coverage in the record.

VSIX digests change on every run because vsce writes timestamps into the zip.
