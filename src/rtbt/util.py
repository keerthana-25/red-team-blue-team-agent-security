from __future__ import annotations

import hashlib
import platform
import sys
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def derive_seed(*parts: object) -> int:
    """A stable, collision-resistant integer seed derived from arbitrary parts.
    Never uses a global RNG, so campaigns run in any order produce the same seeds."""
    raw = ":".join(str(p) for p in parts).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    return int.from_bytes(digest[:8], "big") % (2**31 - 1)


def runtime_environment_info() -> dict[str, str]:
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def use_utf8_output() -> None:
    """Keep printing from crashing on consoles whose default encoding is not UTF-8
    (some Windows setups, redirected output). Unprintable characters become '?'."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


# ---------------------------------------------------------------------------- source provenance
# What counts as "the source" for the manifest's integrity hash: whitelisted, not blacklisted, so
# a new generated-output directory added later is excluded by default rather than accidentally
# swept in. Deliberately excludes results/ (generated), __pycache__, .git, and anything hidden.
_SOURCE_DIRS = ("src", "scenarios", "configs", "web", "docs", "tests")
_SOURCE_FILES = ("run_demo.py", "run_web.py", "start.py", "README.md", "CHANGELOG.md", "pyproject.toml")


def source_tree_hash(root) -> str:
    """A stable SHA-256 over every whitelisted source file's relative path and content, sorted
    for determinism. Used as a stand-in for a Git commit hash so a run can still be tied to an
    exact version of the code and scenarios even when the project is not (or is no longer) a Git
    checkout — this project ships as a plain folder, not a repository, so this is the normal case
    here, not a fallback for a rare one."""
    import pathlib
    root = pathlib.Path(root)
    files = []
    for d in _SOURCE_DIRS:
        for f in sorted((root / d).rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                files.append(f)
    for name in _SOURCE_FILES:
        f = root / name
        if f.exists():
            files.append(f)
    files.sort(key=lambda f: str(f.relative_to(root)))
    digest = hashlib.sha256()
    for f in files:
        digest.update(str(f.relative_to(root)).encode("utf-8"))
        digest.update(b"\x00")
        digest.update(f.read_bytes())
    return digest.hexdigest()


def git_info(root) -> dict[str, Any] | None:
    """None when this isn't a Git checkout — never a fabricated commit hash. Reads .git's refs
    directly rather than shelling out to the git binary: this project already treats "no process
    execution or network access outside netguard.py" as an invariant enforced by its own test
    suite, and a commit hash is cheap to read as plain files without an exception to that rule.
    Dirty-tree detection genuinely does need `git status`, which this deliberately does not run —
    "dirty" is reported as None with a note, rather than guessed or silently omitted."""
    import pathlib
    root = pathlib.Path(root)
    git_dir = root / ".git"
    if not git_dir.is_dir():
        return None
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref_path = git_dir / head.split(" ", 1)[1].strip()
            commit = ref_path.read_text(encoding="utf-8").strip() if ref_path.exists() else None
        else:
            commit = head  # detached HEAD: the hash is written directly
        return {"commit": commit, "dirty": None,
                "dirty_note": "Not checked: detecting a dirty working tree needs the git command-line tool, "
                              "which this project does not invoke as a subprocess. Run 'git status' yourself."}
    except OSError:
        return None


def sha256_file(path) -> str:
    import pathlib
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
