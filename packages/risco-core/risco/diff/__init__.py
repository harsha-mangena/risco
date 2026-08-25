from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from risco.globs import match_first
from risco.models import ChangeStatus, FileCategory

SOURCE_EXTENSIONS = {
    ".ts": "ts",
    ".tsx": "ts",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".py": "py",
}

CODEOWNERS_PATHS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")


@dataclass
class ChangedFile:
    path: str
    status: ChangeStatus
    old_path: Optional[str] = None
    category: FileCategory = FileCategory.OTHER


@dataclass
class ChangedFileSet:
    files: list[ChangedFile] = field(default_factory=list)
    policy_changed: bool = False

    def paths(self) -> list[str]:
        return [f.path for f in self.files]

    def of(self, *cats: FileCategory) -> list[ChangedFile]:
        return [f for f in self.files if f.category in cats]

    def source_files(self) -> list["ChangedFile"]:
        return [f for f in self.files if f.category == FileCategory.SOURCE]


def _effective_path(f: ChangedFile) -> str:
    return f.old_path or f.path if f.status == ChangeStatus.DELETED else f.path


def classify_file(
    f: ChangedFile,
    svc,
    policy_path: str = "risco.yml",
) -> ChangedFile:
    p = _effective_path(f).lstrip("./")
    norm = ChangedFile(path=f.path, status=f.status, old_path=f.old_path)
    if svc.is_migration(p):
        norm.category = FileCategory.MIGRATION
        return norm
    kind = svc.is_contract(p)
    if kind:
        norm.category = FileCategory.CONTRACT
        return norm
    if match_first(p, [policy_path]):
        norm.category = FileCategory.POLICY
        return norm
    if match_first(p, list(CODEOWNERS_PATHS)):
        norm.category = FileCategory.CODEOWNERS
        return norm
    ext = ("." + p.rsplit(".", 1)[-1].lower()) if "." in p.rsplit("/", 1)[-1] else ""
    if ext in SOURCE_EXTENSIONS:
        norm.category = FileCategory.SOURCE
        return norm
    norm.category = FileCategory.OTHER
    return norm


def classify_all(
    entries: list[tuple[str, str, Optional[str]]],
    svc,
    policy_path: str = "risco.yml",
) -> ChangedFileSet:
    out = ChangedFileSet()
    for path, status, old_path in entries:
        cf = classify_file(
            ChangedFile(path=path, status=ChangeStatus(status)),
            svc,
            policy_path,
        )
        out.files.append(cf)
        if cf.category == FileCategory.POLICY:
            out.policy_changed = True
    out.files.sort(key=lambda x: x.path)
    return out


_STATUS_MAP_GITHUB = {
    "added": ChangeStatus.ADDED,
    "modified": ChangeStatus.MODIFIED,
    "removed": ChangeStatus.DELETED,
    "renamed": ChangeStatus.RENAMED,
    "changed": ChangeStatus.MODIFIED,
}


def from_github_files(payload: list[dict]) -> list[tuple[str, str, Optional[str]]]:
    out = []
    for item in payload:
        status = _STATUS_MAP_GITHUB.get(str(item.get("status", "")).lower())
        if status is None:
            continue
        prev = item.get("previous_filename")
        out.append((item.get("filename", ""), status.value, prev))
    return out


def from_git_name_status(text: str) -> list[tuple[str, str, Optional[str]]]:
    out = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) >= 3 and parts[0].startswith("R"):
            score = parts[0][1:]
            try:
                int(score)
                status = "R"
            except ValueError:
                status = "M"
            out.append((parts[2], status, parts[1]))
        elif len(parts) >= 2:
            s = parts[0][:1]
            if s in ("A", "M", "D", "R"):
                out.append((parts[-1], s, None))
    return out


def git_diff_name_status(repo_dir: str, base: str, head: str) -> list[tuple[str, str, Optional[str]]]:
    import subprocess

    proc = subprocess.run(
        ["git", "-C", repo_dir, "diff", "--name-status", "-M", base, head],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git diff failed")
    return from_git_name_status(proc.stdout)
