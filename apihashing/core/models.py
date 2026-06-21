from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class AlgorithmMetadata(BaseModel):
    id: str
    display_name: str
    implementation_type: Literal["python", "c_shared"]
    input_mode: str
    hash_size_bits: int | None = None
    supports_base_values: bool = False
    description: str = ""
    author: str | None = None
    source: str | None = None
    license: str | None = None
    aliases: list[str] = Field(default_factory=list)
    copied_from_flare_shellcode: bool = False
    pack: str
    module_path: str


class CatalogRecord(BaseModel):
    kind: Literal["wordlist"] | None = None
    binary_family: Literal["pe", "elf", "macho"] | None = None
    library: str
    symbols: list[str]
    source_path: Path | None = None


class MergedCatalogResult(BaseModel):
    libraries: list[CatalogRecord]


class MatchRecord(BaseModel):
    pack: str
    algorithm_id: str
    library: str
    symbol: str
    base_value: int | None = None
    catalog_kind: Literal["library", "wordlist"] = "library"
    binary_family: str | None = None
    hash_size_bits: int | None = None
    hash_value_unsigned_int: int
    hash_value_hex: str


class ResolveResult(BaseModel):
    algorithm_id: str
    query_hash_input: str
    query_hash_unsigned_int: int
    query_hash_hex: str
    matches: list[MatchRecord]


class SearchHashResult(BaseModel):
    query_hash_input: str
    query_hash_unsigned_int: int
    query_hash_hex: str
    library_filter: str | None = None
    execution_mode: Literal["single_thread", "threadpool", "process_pool"] | None = None
    worker_count: int | None = None
    algorithm_count: int | None = None
    results: list[MatchRecord]


class HashStringResult(BaseModel):
    algorithm_id: str
    library_name: str
    symbol_name: str
    base_value: int | None = None
    hash_size_bits: int | None = None
    hash_value_unsigned_int: int
    hash_value_hex: str


class HashStringAggregateResult(BaseModel):
    algorithm_id: str
    library_name: str
    symbol_name: str
    results: list[HashStringResult]


class HashStringBatchResult(BaseModel):
    algorithm_id: str
    libraries: list[str]
    symbol_name: str
    results: list[HashStringResult]

    def __getitem__(self, item: str):
        return getattr(self, item)


class ExportedHeaderResult(BaseModel):
    algorithm_id: str
    library: str
    base_value: int | None = None
    hash_size_bits: int | None = None
    enum_name: str
    header_guard: str
    header_text: str


class ExportedHeaderAggregateResult(BaseModel):
    algorithm_id: str
    library_name: str
    results: list[ExportedHeaderResult]

    def __getitem__(self, item: str):
        return getattr(self, item)


class ExportedHeaderBatchResult(BaseModel):
    algorithm_id: str
    libraries: list[str]
    exports: list[ExportedHeaderResult]


class BulkAutoResult(BaseModel):
    algorithm_id: str
    query_hash_input: str
    query_hash_unsigned_int: int
    query_hash_hex: str
    matches: list[MatchRecord]
    exports: list[ExportedHeaderResult]

    def __getitem__(self, item: str):
        return getattr(self, item)


class ValidationReport(BaseModel):
    pack: str
    valid: bool
    errors: list[str] = Field(default_factory=list)


class AnalyzeResult(BaseModel):
    binary_family: str
    imports: list[str]
    exports: list[str]


class PackRuntime(BaseModel):
    root: Path
    name: str
    version: str
    catalogs: list[CatalogRecord]
    algorithms: list[AlgorithmMetadata]

    model_config = {"arbitrary_types_allowed": True}
