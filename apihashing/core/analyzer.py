from __future__ import annotations

import tempfile
from pathlib import Path

import lief

from apihashing.core.models import AnalyzeResult, CatalogRecord


def _parse_binary(blob: bytes):
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(blob)
        temp_path = Path(handle.name)
    try:
        binary = lief.parse(str(temp_path))
        if binary is None:
            raise ValueError("Unable to parse binary")
        return binary
    finally:
        temp_path.unlink(missing_ok=True)


def _entry_name(entry) -> str | None:
    name = getattr(entry, "name", None)
    if name:
        return str(name)
    text = str(entry).strip()
    if ": " in text and " (" in text:
        text = text.split(": ", 1)[1].split(" (", 1)[0]
    return text or None


def analyze_binary_blob(blob: bytes) -> AnalyzeResult:
    binary = _parse_binary(blob)
    format_name = binary.format.name.lower()
    imports: list[str] = []
    exports: list[str] = []
    if hasattr(binary, "imports"):
        for entry in binary.imports:
            name = _entry_name(entry)
            if name:
                imports.append(name)
    if hasattr(binary, "exported_functions"):
        exports = [name for name in (_entry_name(item) for item in binary.exported_functions) if name]
    elif hasattr(binary, "exported_symbols"):
        exports = [name for name in (_entry_name(item) for item in binary.exported_symbols) if name]
    return AnalyzeResult(binary_family=format_name, imports=sorted(set(imports)), exports=sorted(set(exports)))


def build_catalog_from_binary_blob(filename: str, blob: bytes) -> CatalogRecord:
    analysis = analyze_binary_blob(blob)
    return CatalogRecord(
        kind=None,
        binary_family=analysis.binary_family,
        library=filename,
        symbols=analysis.exports,
        source_path=None,
    )


def build_catalog_from_binary_path(path: Path) -> CatalogRecord:
    return build_catalog_from_binary_blob(path.name, path.read_bytes())
