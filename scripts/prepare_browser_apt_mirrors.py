"""Choose a responsive known Ubuntu mirror on the disposable browser runner.

APT retains its existing signed repository metadata and package verification.
"""
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import re
import subprocess

AZURE = "http://azure.archive.ubuntu.com/ubuntu/"
ARCHIVE = "https://archive.ubuntu.com/ubuntu/"
SECURITY = "https://security.ubuntu.com/ubuntu/"
ORIGINAL = {AZURE: "priority:1", ARCHIVE: "priority:2", SECURITY: "priority:3"}
PREFERRED = {ARCHIVE: "priority:1", SECURITY: "priority:2", AZURE: "priority:3"}
KNOWN = (AZURE, ARCHIVE, SECURITY)


def preferred_mirrors(raw: str, ordered: tuple[str, ...] = (ARCHIVE, SECURITY, AZURE)) -> str:
    """Reject unknown mirrors, priority drift, and unexpected output choices."""
    rows = [line.split() for line in raw.splitlines()]
    if len(rows) != 3 or any(len(row) != 2 for row in rows):
        raise ValueError("Unexpected browser runner APT mirror format")
    found = dict(rows)
    if len(found) != 3 or set(found) != set(KNOWN) or set(found.values()) != {"priority:1", "priority:2", "priority:3"}:
        raise ValueError("Unexpected browser runner APT mirror identity/priority")
    if len(ordered) != 3 or set(ordered) != set(KNOWN):
        raise ValueError("Unexpected browser runner APT mirror choice")
    return "".join(f"{uri}\tpriority:{index}\n" for index, uri in enumerate(ordered, 1))


def responsive_mirrors(suite: str) -> tuple[str, ...]:
    """Probe official release indexes within a bounded deadline per endpoint."""
    if not re.fullmatch(r"[a-z]+", suite):
        raise ValueError("Unexpected Ubuntu suite")
    reachable, unavailable = [], []
    for uri in KNOWN:
        try:
            request = Request(f"{uri}dists/{suite}/InRelease", method="HEAD")
            with urlopen(request, timeout=3) as response:
                if response.status != 200:
                    raise ValueError("Unexpected mirror response")
            reachable.append(uri)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            unavailable.append(uri)
    if not reachable:
        raise ValueError("No known Ubuntu mirror is reachable")
    return tuple(reachable + unavailable)


def main() -> None:
    path = Path("/etc/apt/apt-mirrors.txt")
    raw = path.read_text()
    preferred_mirrors(raw)  # Validate before any network access or write.
    suite = subprocess.check_output(["lsb_release", "-cs"], text=True, timeout=5).strip()
    replacement = preferred_mirrors(raw, responsive_mirrors(suite))
    path.write_text(replacement)
    Path("/etc/apt/apt.conf.d/zz-djc-browser-acquire").write_text(
        'Acquire::Retries "1";\n'
        'Acquire::http::Timeout "5";\n'
        'Acquire::https::Timeout "5";\n'
    )
    print("Browser APT: reachable known Ubuntu mirrors preferred; retries=1, timeout=5s")


if __name__ == "__main__":
    main()
