from __future__ import annotations

import json
import lzma
from pathlib import Path
from typing import Any

import yaml

from apihashing.core.algorithms import AlgorithmRegistry, load_native_algorithms, load_python_algorithms
from apihashing.core.models import CatalogRecord, PackRuntime, ValidationReport


class PackLoader:
    def __init__(self, pack_roots: list[Path]) -> None:
        self.pack_roots = pack_roots

    def load(self) -> tuple[list[PackRuntime], AlgorithmRegistry]:
        registry = AlgorithmRegistry()
        packs: list[PackRuntime] = []
        for pack_root in self.pack_roots:
            runtime, loaded_algorithms = self._load_pack(pack_root)
            for loaded in loaded_algorithms:
                registry.register(loaded)
            packs.append(runtime)
        return packs, registry

    def validate(self, pack_path: Path) -> ValidationReport:
        errors: list[str] = []
        try:
            self._load_pack(pack_path)
        except Exception as exc:
            errors.append(str(exc))
        return ValidationReport(pack=pack_path.name, valid=not errors, errors=errors)

    def _load_pack(self, pack_root: Path):
        manifest = self._read_manifest(pack_root)
        pack_name = str(manifest.get("name", pack_root.name))
        version = str(manifest.get("version", "0.1.0"))
        catalogs = self._discover_catalogs(pack_root)
        loaded_algorithms = self._discover_python_algorithms(pack_root, pack_name)
        loaded_algorithms.extend(self._discover_native_algorithms(pack_root, pack_name))
        runtime = PackRuntime(
            root=pack_root,
            name=pack_name,
            version=version,
            catalogs=catalogs,
            algorithms=[item.metadata for item in loaded_algorithms],
        )
        return runtime, loaded_algorithms

    def _discover_catalogs(self, pack_root: Path) -> list[CatalogRecord]:
        catalogs: list[CatalogRecord] = []
        catalogs_root = pack_root / "catalogs"
        if not catalogs_root.exists():
            return catalogs
        catalog_paths = sorted(catalogs_root.rglob("*.json")) + sorted(catalogs_root.rglob("*.json.xz"))
        for catalog_path in catalog_paths:
            payload = self._read_catalog_document(catalog_path)
            if "libraries" in payload:
                catalogs.extend(
                    self._catalog_record_from_payload(item, catalog_path)
                    for item in payload.get("libraries", [])
                    if isinstance(item, dict)
                )
            else:
                catalogs.append(self._catalog_record_from_payload(payload, catalog_path))
        return catalogs

    def _discover_python_algorithms(self, pack_root: Path, pack_name: str):
        loaded = []
        algorithms_root = pack_root / "algorithms"
        if not algorithms_root.exists():
            return loaded
        module_paths = sorted(
            path
            for path in algorithms_root.rglob("*.py")
            if path.name != "__init__.py"
            and not path.name.startswith("_")
            and "native" not in path.relative_to(algorithms_root).parts
            and not any(part.startswith("_") for part in path.relative_to(algorithms_root).parts[:-1])
        )
        for module_path in module_paths:
            loaded.extend(load_python_algorithms(module_path, pack_name))
        return loaded

    def _discover_native_algorithms(self, pack_root: Path, pack_name: str):
        loaded = []
        native_root = pack_root / "algorithms" / "native"
        if not native_root.exists():
            return loaded
        for module_path in sorted(native_root.rglob("*.hash.so")):
            try:
                loaded.extend(load_native_algorithms(module_path, pack_name))
            except Exception:
                # Keep pack loading resilient across platforms where bundled
                # shared objects may be unavailable or ABI-incompatible.
                continue
        return loaded

    def _read_manifest(self, pack_root: Path) -> dict[str, Any]:
        manifest_path = pack_root / "pack.yaml"
        if not manifest_path.exists():
            return {}
        with manifest_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Invalid manifest in {manifest_path}")
        return data

    @staticmethod
    def _read_catalog_document(catalog_path: Path) -> dict[str, Any]:
        if catalog_path.name.endswith(".json.xz"):
            raw = lzma.decompress(catalog_path.read_bytes()).decode("utf-8")
        else:
            raw = catalog_path.read_text(encoding="utf-8")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError(f"Invalid catalog in {catalog_path}")
        return payload

    @staticmethod
    def _catalog_record_from_payload(payload: dict[str, Any], source_path: Path | None = None) -> CatalogRecord:
        if "library" in payload:
            return CatalogRecord(
                kind="wordlist" if payload.get("kind") == "wordlist" else None,
                binary_family=payload.get("binary_family"),
                library=str(payload["library"]),
                symbols=[str(item) for item in payload.get("symbols", [])],
                source_path=source_path,
            )
        if "name" in payload:
            return CatalogRecord(
                kind="wordlist",
                binary_family=None,
                library=str(payload["name"]),
                symbols=[str(item) for item in payload.get("symbols", [])],
                source_path=source_path,
            )
        raise ValueError(f"Catalog payload must contain either 'library' or 'name': {source_path or '<memory>'}")
