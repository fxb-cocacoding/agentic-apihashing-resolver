from __future__ import annotations

import re
import zlib

from apihashing.core.models import CatalogRecord, ExportedHeaderResult
from apihashing.plugin_api import HashValue


_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
    "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
    "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
    "union", "unsigned", "void", "volatile", "while", "_alignas", "_alignof", "_atomic", "_bool",
    "_complex", "_generic", "_imaginary", "_noreturn", "_static_assert", "_thread_local",
}


def _stable_suffix(value: str) -> str:
    return f"{zlib.crc32(value.encode('utf-8')) & 0xFFFFFFFF:08X}"


def _sanitize_identifier(value: str) -> str:
    normalized = re.sub(r'[.\-?@#\s]+', '_', value)
    normalized = re.sub(r'[^0-9A-Za-z_]+', '_', normalized)
    normalized = re.sub(r'_+', '_', normalized).strip('_')
    if not normalized:
        normalized = 'value'
    if normalized[0].isdigit():
        normalized = f'ID_{normalized}'
    if normalized.lower() in _C_KEYWORDS:
        normalized = f'ID_{normalized}'
    return normalized


def _unique_identifier(value: str, seen: set[str]) -> str:
    base = _sanitize_identifier(value)
    candidate = base
    if len(candidate) > 180:
        candidate = f"{candidate[:171]}_{_stable_suffix(value)}"
    if candidate in seen:
        candidate = f"{candidate}_{_stable_suffix(value)}"
    seen.add(candidate)
    return candidate


def render_c_header_enum(
    *,
    algorithm_id: str,
    catalog: CatalogRecord,
    entries: list[tuple[str, HashValue]],
    hash_size_bits: int | None,
) -> ExportedHeaderResult:
    if hash_size_bits and hash_size_bits > 32:
        raise ValueError('C enum export currently supports hash widths up to 32 bits only')

    prefix = f'apihashing_{algorithm_id}_{catalog.library}'
    seen_identifiers: set[str] = set()
    enum_name = _unique_identifier(prefix, seen_identifiers)
    lines = [
        'typedef enum {',
    ]
    for symbol_name, hash_value in entries:
        member_name = _unique_identifier(f'{prefix}_{symbol_name}', seen_identifiers)
        lines.append(f'    {member_name} = 0x{hash_value.to_unsigned_int():X},')
    lines.extend([
        f'}} {enum_name};',
        '',
    ])
    return ExportedHeaderResult(
        algorithm_id=algorithm_id,
        library=catalog.library,
        hash_size_bits=hash_size_bits,
        enum_name=enum_name,
        header_guard=f'{enum_name}_H',
        header_text='\n'.join(lines),
    )
