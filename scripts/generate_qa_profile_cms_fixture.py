"""Generate two correctly signed public fake CMS fixtures; never native proof.
Tooling: cryptography46.0.3, asn1crypto1.5.1. No exported private keys.
"""
from pathlib import Path
import subprocess,sys,tempfile,json
root=Path(__file__).resolve().parent.parent
source=(root/'qualification/rendezvous/build_synthetic_receipts.py').read_text()
assert source.count('for variant in variants:')==1
assert source.count("fields={2:b'ZEML4LPXH4.dev.djconnect.ios'")==1
cases={}
with tempfile.TemporaryDirectory(prefix='djc-qa-cms-fixture-') as temporary:
    for label,app in [('qa','ZEML4LPXH4.dev.djconnect.ios.vibecastqa'),('production','ZEML4LPXH4.dev.djconnect.ios')]:
        text=source.replace('for variant in variants:',"for variant in ['valid']:").replace("fields={2:b'ZEML4LPXH4.dev.djconnect.ios'", "fields={2:b'"+app+"'")
        script=Path(temporary)/(label+'.py');out=Path(temporary)/(label+'.json');script.write_text(text)
        subprocess.run([sys.executable,str(script),str(out)],check=True)
        cases[label]=json.loads(out.read_text())['cases'][0]
(root/'qualification/rendezvous/qa-profile-cms-fixtures.json').write_text(json.dumps({'scope':'PUBLIC_SYNTHETIC_SIGNED_CMS_NOT_APPLE_OR_NATIVE','cases':cases},indent=2)+'\n')
