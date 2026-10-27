"""Run bounded source tests; never install, migrate, sign or contact a provider."""
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys

root = Path(__file__).resolve().parent
if sys.version_info[:2] != (3, 14):
    raise SystemExit("Source qualification requires CPython 3.14; no interpreter fallback")
if not os.environ.get("TMPDIR") or not Path(os.environ["TMPDIR"]).is_dir():
    raise SystemExit("Explicit external/runner scratch TMPDIR required")
manifest = json.loads((root / "source-manifest.json").read_text())
for relative, expected in manifest["inputs_sha256"].items():
    actual = hashlib.sha256((root.parent / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit("Source manifest mismatch: " + relative)
env = {**os.environ, "PYTHONPATH": str(root / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(root / "tests"), "-v"],
                        env=env, timeout=60, capture_output=True, text=True)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
print(json.dumps({"classification": "SOURCE_QUALIFICATION_ONLY", "exit_code": result.returncode,
                  "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                  "platform": platform.system(), "native_provider_or_network_effects": False,
                  "Linux_clock_or_VFS_powerloss_qualified": False,
                  "input_count": len(manifest["inputs_sha256"])}))
raise SystemExit(result.returncode)
