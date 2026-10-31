"""Unzip a VSIX the way an editor installs it. usage: python3 -I unzip.py in.vsix outdir"""
import sys
import zipfile

zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
