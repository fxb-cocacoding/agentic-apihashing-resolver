from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path


PACK_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")


@dataclass(frozen=True)
class InitWorkspaceResult:
    workspace_root: Path
    packs_root: Path
    created_pack_path: Path
    copied_bundled_pack_paths: list[Path]


def discover_pack_roots(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        path
        for path in root.iterdir()
        if path.is_dir() and ((path / "algorithms").exists() or (path / "catalogs").exists())
    )


def bundled_packs_root() -> Path | None:
    try:
        resource = files("apihashing").joinpath("bundled_packs")
        if not resource.is_dir():
            return None
        return Path(str(resource))
    except Exception:
        return None


def build_pack_skeleton(pack_root: Path) -> None:
    (pack_root / "algorithms" / "python").mkdir(parents=True, exist_ok=True)
    (pack_root / "algorithms" / "native").mkdir(parents=True, exist_ok=True)
    (pack_root / "catalogs" / "pe").mkdir(parents=True, exist_ok=True)
    (pack_root / "catalogs" / "elf").mkdir(parents=True, exist_ok=True)
    (pack_root / "catalogs" / "macho").mkdir(parents=True, exist_ok=True)
    (pack_root / "catalogs" / "wordlists").mkdir(parents=True, exist_ok=True)
    (pack_root / "tests").mkdir(parents=True, exist_ok=True)
    readme_path = pack_root / "README.md"
    if not readme_path.exists():
        readme_path.write_text(
            (
                f"# {pack_root.name}\n\n"
                "External API-hashing pack.\n\n"
                "- Add one hash per file under `algorithms/`\n"
                "- Add library and wordlist catalogs under `catalogs/`\n"
                "- Keep this repository independent from the core engine repository\n"
            ),
            encoding="utf-8",
        )


def copy_bundled_packs(destination_packs_root: Path) -> list[Path]:
    source = bundled_packs_root()
    if source is None:
        return []
    destination_packs_root.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for pack_root in discover_pack_roots(source):
        target = destination_packs_root / pack_root.name
        if target.exists():
            continue
        shutil.copytree(pack_root, target, dirs_exist_ok=False)
        copied.append(target)
    return copied


def init_workspace(
    workspace_root: Path,
    *,
    pack_name: str,
    include_bundled_packs: bool = True,
) -> InitWorkspaceResult:
    normalized_pack_name = pack_name.strip().lower()
    if not PACK_NAME_RE.fullmatch(normalized_pack_name):
        raise ValueError(
            "Invalid pack name. Use 2-128 chars: lowercase letters, digits, '.', '_', '-' and start with a letter/digit."
        )
    workspace_root = workspace_root.resolve()
    packs_root = workspace_root / "packs"
    packs_root.mkdir(parents=True, exist_ok=True)
    copied = copy_bundled_packs(packs_root) if include_bundled_packs else []
    created_pack_path = packs_root / normalized_pack_name
    if created_pack_path.exists():
        raise ValueError(f"Pack already exists: {created_pack_path}")
    build_pack_skeleton(created_pack_path)
    return InitWorkspaceResult(
        workspace_root=workspace_root,
        packs_root=packs_root,
        created_pack_path=created_pack_path,
        copied_bundled_pack_paths=copied,
    )
