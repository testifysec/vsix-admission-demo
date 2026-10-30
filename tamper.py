"""Repack a VSIX with a line prepended to extension/extension.js.

Stands in for the 2.1.313 attack: same publisher, same name, same version,
same manifest, one changed file. The prepended line is inert.

usage: python3 -I tamper.py in.vsix out.vsix
"""
import sys
import zipfile

LOADER = b'globalThis.__injected = "stand-in for a 66-line loader";\n'

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        data = zin.read(info.filename)
        if info.filename == "extension/extension.js":
            data = LOADER + data
        zout.writestr(info, data)
