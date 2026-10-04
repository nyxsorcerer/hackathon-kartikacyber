"""Apply the recorded compatible dependency fix to both Pi's SDK and compiled CLI."""
import base64
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path

ROOT = Path('/opt/numen')
PACKAGE = ROOT/'node_modules/@earendil-works/pi-coding-agent'
VERSION = '5.0.12'
INTEGRITY = 'sha512-YovQ3rzhaLMIrDjNDMkNS01tea93qhEhG5xy8f6+R0l+dw3Ki+5sCoIoI942iuLZTHWogWktgwVDhU09iNEimQ=='
RESOLVED = 'https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.12.tgz'
TARBALL = Path('/opt/numen/brace-expansion-5.0.12.tgz')
BUNDLE = PACKAGE/'dist/bundle/chunks/chunk-33XOIQ5N.js'
EXPECTED_BUNDLE_SHA256 = '1fbf59b1126d78129049710d1c825afaf3a905333a62a680fdb2174fdb6d3aca'
OLD_FUNCTION = r'''function expand(str2,options={}){if(!str2)return[];let{max=EXPANSION_MAX,maxLength=EXPANSION_MAX_LENGTH}=options;return str2.slice(0,2)==="{}"&&(str2="\\{\\}"+str2.slice(2)),expand_(escapeBraces(str2),max,maxLength,!0).map(unescapeBraces)}'''
NEW_FUNCTION = 'function expand(str2,options={}){return numenPatchedExpand(str2,options)}'

raw = TARBALL.read_bytes()
assert 'sha512-'+base64.b64encode(hashlib.sha512(raw).digest()).decode() == INTEGRITY
assert json.loads((PACKAGE/'package.json').read_text())['version'] == '1.0.0'
assert json.loads((PACKAGE/'node_modules/balanced-match/package.json').read_text())['version'] == '4.0.4'
bundle = BUNDLE.read_bytes()
assert hashlib.sha256(bundle).hexdigest() == EXPECTED_BUNDLE_SHA256
source = bundle.decode()
assert source.count(OLD_FUNCTION) == 1
replacement = PACKAGE/'node_modules/brace-expansion'
shutil.rmtree(replacement)
replacement.mkdir()
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
    total = 0
    for member in archive.getmembers():
        parts = Path(member.name).parts
        assert parts[0] == 'package' and '..' not in parts and not member.name.startswith('/')
        assert member.isdir() or member.isreg()
        target = replacement.joinpath(*parts[1:])
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            total += member.size
            assert total <= 1024*1024
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
# npm's published shrinkwrap overrides the outer lock during ci. Repair the actual installed graph.
for path, key in [(ROOT/'package-lock.json','node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion'),
                  (ROOT/'node_modules/.package-lock.json','node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion'),
                  (PACKAGE/'npm-shrinkwrap.json','node_modules/brace-expansion')]:
    lock = json.loads(path.read_text())
    lock['packages'][key].update(version=VERSION, resolved=RESOLVED, integrity=INTEGRITY)
    path.write_text(json.dumps(lock, indent=2)+'\n')
# The published CLI also embeds the old implementation; route its exact entry point to the verified patched module.
source = 'import {expand as numenPatchedExpand} from "../../../node_modules/brace-expansion/dist/esm/index.js";\n'+source.replace(OLD_FUNCTION, NEW_FUNCTION)
assert hashlib.sha256(source.encode()).hexdigest() == "140daad3badc613549342760f22fade24121fb332cdbead61fa6719479df85f0"
BUNDLE.write_text(source)
print(json.dumps({'brace_expansion':VERSION,'cli_bundle_sha256':hashlib.sha256(source.encode()).hexdigest()}))
