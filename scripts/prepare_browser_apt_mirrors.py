"""Prefer the runner's existing HTTPS Ubuntu archives for browser dependencies.

Only the disposable browser CI runner is changed. Ubuntu signing keys, suites,
package verification and the workflow/test deadlines remain unchanged.
"""
from pathlib import Path


AZURE = "http://azure.archive.ubuntu.com/ubuntu/"
ARCHIVE = "https://archive.ubuntu.com/ubuntu/"
SECURITY = "https://security.ubuntu.com/ubuntu/"
ORIGINAL = {AZURE: "priority:1", ARCHIVE: "priority:2", SECURITY: "priority:3"}
PREFERRED = {ARCHIVE: "priority:1", SECURITY: "priority:2", AZURE: "priority:3"}


def preferred_mirrors(raw: str) -> str:
    """Fail before writing if the hosted image's known mirror set has drifted."""
    rows = [line.split() for line in raw.splitlines()]
    if len(rows) != 3 or any(len(row) != 2 for row in rows):
        raise ValueError("Unexpected browser runner APT mirror format")
    found = dict(rows)
    if len(found) != 3 or found not in (ORIGINAL, PREFERRED):
        raise ValueError("Unexpected browser runner APT mirror identity/priority")
    return "".join(f"{uri}\t{priority}\n" for uri, priority in PREFERRED.items())


def main() -> None:
    path = Path("/etc/apt/apt-mirrors.txt")
    replacement = preferred_mirrors(path.read_text())
    path.write_text(replacement)
    # The last-sorting file overrides image defaults without disabling checks.
    Path("/etc/apt/apt.conf.d/zz-djc-browser-acquire").write_text(
        'Acquire::Retries "1";\n'
        'Acquire::http::Timeout "15";\n'
        'Acquire::https::Timeout "15";\n'
    )
    print("Browser APT: existing HTTPS Ubuntu archives preferred; retries=1, timeout=15s")


if __name__ == "__main__":
    main()
