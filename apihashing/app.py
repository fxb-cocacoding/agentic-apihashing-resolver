from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, model_validator

from apihashing.core.models import (
    BulkAutoResult,
    ExportedHeaderAggregateResult,
    ExportedHeaderBatchResult,
    ExportedHeaderResult,
    HashStringAggregateResult,
    HashStringBatchResult,
    HashStringResult,
    ResolveResult,
    SearchHashResult,
)
from apihashing.core.pack_loader import PackLoader
from apihashing.core.service import ApiHashService


class ResolveRequest(BaseModel):
    hash_value: int | str
    algorithm_id: str
    library_names: list[str] | None = None
    catalog_names: list[str] | None = None
    xor_value: int | str | None = None
    algorithm_params: dict[str, object] | None = None
    exclude_hyphenated_dlls: bool = False
    common_windows_dlls_only: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "hash_value": "0x7c0017bb",
                    "algorithm_id": "ror13_add",
                    "algorithm_params": {"base_values": ["0x10", "0x20"]},
                    "library_names": ["kernel32.dll"],
                }
            ]
        }
    )


class SearchHashRequest(BaseModel):
    hash_value: int | str
    algorithm_id: str | None = None
    library_name: str | None = None
    library_names: list[str] | None = None
    catalog_names: list[str] | None = None
    catalogs: list[dict[str, object]] | None = None
    xor_value: int | str | None = None
    algorithm_params: dict[str, object] | None = None
    exclude_hyphenated_dlls: bool = False
    common_windows_dlls_only: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "hash_value": "0x7c0017bb",
                    "library_names": ["kernel32.dll"],
                    "algorithm_params": {"base_values": ["0x10", "0x20"]},
                }
            ]
        }
    )

    @model_validator(mode="after")
    def validate_selector_conflicts(self) -> "SearchHashRequest":
        library_name = (self.library_name or "").strip()
        if library_name and (self.library_names or self.catalog_names):
            raise ValueError("library_name cannot be combined with library_names or catalog_names")
        self.library_name = library_name or None
        return self


class HashStringRequest(BaseModel):
    algorithm_id: str
    symbol_name: str
    library_name: str = ""
    library_names: list[str] | None = None
    catalog_names: list[str] | None = None
    xor_value: int | str | None = None
    algorithm_params: dict[str, object] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "algorithm_id": "ror13_add",
                    "symbol_name": "CreateFileW",
                    "library_name": "kernel32.dll",
                    "algorithm_params": {"base_values": ["0x10", "0x20"]},
                }
            ]
        }
    )

    @model_validator(mode="after")
    def validate_selector_conflicts(self) -> "HashStringRequest":
        library_name = self.library_name.strip()
        if library_name and (self.library_names or self.catalog_names):
            raise ValueError("library_name cannot be combined with library_names or catalog_names")
        self.library_name = library_name
        return self


class ValidatePackRequest(BaseModel):
    pack_path: str

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "pack_path": "packs/default-pack",
                }
            ]
        }
    )


class ScaffoldAlgorithmRequest(BaseModel):
    pack_path: str
    algorithm_id: str
    language: str

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "pack_path": "packs/default-pack",
                    "algorithm_id": "custom_crc32_variant",
                    "language": "python",
                }
            ]
        }
    )


class ExportEnumRequest(BaseModel):
    algorithm_id: str
    library_name: str | None = None
    library_names: list[str] | None = None
    catalog_names: list[str] | None = None
    catalogs: list[dict[str, object]] | None = None
    xor_value: int | str | None = None
    algorithm_params: dict[str, object] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "algorithm_id": "ror13_add",
                    "library_name": "kernel32.dll",
                    "algorithm_params": {"base_values": ["0x10", "0x20"]},
                }
            ]
        }
    )

    @model_validator(mode="after")
    def validate_selector_conflicts(self) -> "ExportEnumRequest":
        library_name = (self.library_name or "").strip()
        if library_name and (self.library_names or self.catalog_names):
            raise ValueError("library_name cannot be combined with library_names or catalog_names")
        self.library_name = library_name or None
        return self


class PackToggleRequest(BaseModel):
    active: bool

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "active": True,
                }
            ]
        }
    )


class BulkAutoRequest(BaseModel):
    hash_value: int | str
    algorithm_id: str
    library_names: list[str] | None = None
    catalog_names: list[str] | None = None
    catalogs: list[dict[str, object]] | None = None
    xor_value: int | str | None = None
    algorithm_params: dict[str, object] | None = None
    exclude_hyphenated_dlls: bool = False
    common_windows_dlls_only: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "hash_value": "0x7c0017bb",
                    "algorithm_id": "ror13_add",
                    "library_names": ["kernel32.dll"],
                    "algorithm_params": {"base_values": ["0x10", "0x20"]},
                }
            ]
        }
    )


class HuntRequest(BaseModel):
    hashes: list[int | str]
    xor_value: int | str | None = None
    algorithm_params: dict[str, object] | None = None

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "hashes": ["0x7c0017bb", "0xdeadbeef"],
                    "xor_value": "0x13579bdf",
                }
            ]
        }
    )


class NativeRebuildRequest(BaseModel):
    pack_names: list[str] | None = None
    target: str = "all"

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "pack_names": ["default-pack"],
                    "target": "all",
                }
            ]
        }
    )


def create_app(project_root: Path | None = None) -> FastAPI:
    project_root = project_root or Path(__file__).resolve().parents[1]
    app = FastAPI(
        title="apihashing",
        description="API hashing service for malware analysis. Swagger UI documents routes and request examples.",
        version="0.1.0",
    )
    app.state.service = ApiHashService.from_project_root(project_root)

    @app.get("/health", summary="Health check", description="Simple liveness check for the backend service.")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/admin/reload", summary="Reload runtime", description="Reload packs, algorithms, and catalogs without restarting the server.")
    async def admin_reload():
        try:
            return app.state.service.reload_runtime()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/admin/rebuild-native", summary="Rebuild native plugins", description="Run `make` for native pack plugins, then reload runtime state.")
    async def admin_rebuild_native(payload: NativeRebuildRequest):
        try:
            return app.state.service.rebuild_native_plugins(pack_names=payload.pack_names, target=payload.target)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/packs", summary="List packs", description="List discovered packs and their active session state.")
    async def list_packs() -> list[dict[str, object]]:
        return app.state.service.list_packs()

    @app.post("/packs/{pack_name}", summary="Toggle pack", description="Activate or deactivate one pack in the current runtime session.")
    async def set_pack_active(pack_name: str, payload: PackToggleRequest):
        try:
            return app.state.service.set_pack_active(pack_name, payload.active)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/algorithms", summary="List algorithms", description="List loaded hash algorithms with metadata and capabilities.")
    async def list_algorithms():
        return [algorithm.model_dump(mode="json", exclude_none=True) for algorithm in app.state.service.list_algorithms()]

    @app.get("/catalogs", summary="List catalogs", description="List loaded catalogs (libraries and wordlists) with export counts.")
    async def list_catalogs(
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
        filter_text: str | None = None,
        sort_by: str = "name",
        sort_direction: str = "asc",
    ):
        return [
            {
                **catalog.model_dump(mode="json", exclude_none=True),
                "export_count": len(catalog.symbols),
            }
            for catalog in app.state.service.list_catalogs(
                exclude_hyphenated_dlls=exclude_hyphenated_dlls,
                common_windows_dlls_only=common_windows_dlls_only,
                filter_text=filter_text,
                sort_by=sort_by,
                sort_direction=sort_direction,
            )
        ]

    @app.get("/hash", summary="HashDB algorithms", description="HashDB-compatible route listing algorithms.")
    async def hashdb_algorithms():
        return {"algorithms": app.state.service.list_hashdb_algorithms()}

    @app.get("/hash/{algorithm_id}/{hash_value}", summary="HashDB lookup", description="HashDB-compatible lookup for one algorithm and one hash value.")
    async def hashdb_lookup(algorithm_id: str, hash_value: str, xor_value: str | None = None):
        return app.state.service.hashdb_lookup(algorithm_id, hash_value, xor_value=xor_value)

    @app.get("/module/{module_name}/{algorithm_id}/", summary="HashDB module hashes", description="HashDB-compatible export of all hashes for a module and algorithm.")
    async def hashdb_module_hashes_default(module_name: str, algorithm_id: str):
        return app.state.service.hashdb_module_hashes(module_name, algorithm_id, "")

    @app.get("/module/{module_name}/{algorithm_id}/{permutation}", summary="HashDB module hashes (permutation)", description="HashDB-compatible export of module hashes with permutation parameter.")
    async def hashdb_module_hashes(module_name: str, algorithm_id: str, permutation: str):
        return app.state.service.hashdb_module_hashes(module_name, algorithm_id, permutation)

    @app.post("/hunt", summary="HashDB hunt", description="HashDB-compatible hunt operation for one or more observed hash values.")
    async def hashdb_hunt(payload: HuntRequest):
        return app.state.service.hashdb_hunt(payload.hashes, xor_value=payload.xor_value)

    @app.post("/resolve", response_model=ResolveResult, summary="Resolve hash", description="Resolve one observed hash against selected algorithm and catalogs/libraries.")
    async def resolve(payload: ResolveRequest) -> ResolveResult:
        try:
            return app.state.service.resolve_hash(
                payload.hash_value,
                payload.algorithm_id,
                xor_value=payload.xor_value,
                algorithm_params=payload.algorithm_params,
                library_names=payload.library_names,
                catalog_names=payload.catalog_names,
                exclude_hyphenated_dlls=payload.exclude_hyphenated_dlls,
                common_windows_dlls_only=payload.common_windows_dlls_only,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/search-hash", response_model=SearchHashResult, summary="Search hash", description="Search one observed hash across loaded algorithms and selected libraries.")
    async def search_hash(payload: SearchHashRequest) -> SearchHashResult:
        service = app.state.service
        transient_catalogs = [PackLoader._catalog_record_from_payload(item) for item in (payload.catalogs or [])]
        try:
            return (
                service.search_hash_across_algorithms(
                    payload.hash_value,
                    algorithm_id=payload.algorithm_id,
                    library_filter=payload.library_name,
                    library_names=payload.library_names,
                    catalog_names=payload.catalog_names,
                    xor_value=payload.xor_value,
                    algorithm_params=payload.algorithm_params,
                    exclude_hyphenated_dlls=payload.exclude_hyphenated_dlls,
                    common_windows_dlls_only=payload.common_windows_dlls_only,
                )
                if not transient_catalogs
                else service.search_hash_in_catalogs(
                    payload.hash_value,
                    service.get_catalogs_for_query(
                        transient_catalogs,
                        catalog_names=payload.catalog_names,
                        exclude_hyphenated_dlls=payload.exclude_hyphenated_dlls,
                        common_windows_dlls_only=payload.common_windows_dlls_only,
                    ),
                    library_filter=payload.library_name,
                    algorithm_id=payload.algorithm_id,
                    library_names=payload.library_names,
                    xor_value=payload.xor_value,
                    algorithm_params=payload.algorithm_params,
                    exclude_hyphenated_dlls=payload.exclude_hyphenated_dlls,
                    common_windows_dlls_only=payload.common_windows_dlls_only,
                )
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/hash-string", response_model=HashStringResult | HashStringAggregateResult | HashStringBatchResult, summary="Hash string", description="Hash one string/symbol with a selected algorithm and optional library scope.")
    async def hash_string(payload: HashStringRequest) -> HashStringResult | HashStringAggregateResult | HashStringBatchResult:
        try:
            if not payload.library_names and not payload.catalog_names:
                return app.state.service.hash_string_for_algorithm(
                    algorithm_id=payload.algorithm_id,
                    symbol_name=payload.symbol_name,
                    library_name=payload.library_name or "",
                    xor_value=payload.xor_value,
                    algorithm_params=payload.algorithm_params,
                )

            if payload.catalog_names:
                selected_catalogs = app.state.service.get_catalogs_for_query(catalog_names=payload.catalog_names)
                return app.state.service.hash_string_for_catalogs(
                    algorithm_id=payload.algorithm_id,
                    symbol_name=payload.symbol_name,
                    catalogs=selected_catalogs,
                    library_names=payload.library_names,
                    xor_value=payload.xor_value,
                    algorithm_params=payload.algorithm_params,
                )

            return app.state.service.hash_string_for_libraries(
                algorithm_id=payload.algorithm_id,
                symbol_name=payload.symbol_name,
                library_names=payload.library_names,
                xor_value=payload.xor_value,
                algorithm_params=payload.algorithm_params,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/build-catalogs", summary="Build catalogs", description="Create transient catalog JSON from uploaded library binaries.")
    async def build_catalogs(binaries: list[UploadFile] = File(...)):
        try:
            payload = [(binary.filename or "unknown", await binary.read()) for binary in binaries]
            return app.state.service.build_catalogs_from_binaries(payload).model_dump(mode="json", exclude_none=True)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/export-enum", response_model=ExportedHeaderResult | ExportedHeaderAggregateResult | ExportedHeaderBatchResult, summary="Export enum", description="Render C enums for selected libraries and one algorithm.")
    async def export_enum(payload: ExportEnumRequest) -> ExportedHeaderResult | ExportedHeaderAggregateResult | ExportedHeaderBatchResult:
        try:
            transient_catalogs = [PackLoader._catalog_record_from_payload(item) for item in (payload.catalogs or [])]
            libraries = payload.library_names or ([payload.library_name] if payload.library_name else [])
            catalogs = app.state.service.get_catalogs_for_query(transient_catalogs, catalog_names=payload.catalog_names)
            if payload.library_name and not payload.library_names:
                return app.state.service.export_enum_for_library(
                    payload.algorithm_id,
                    payload.library_name,
                    catalogs=catalogs,
                    xor_value=payload.xor_value,
                    algorithm_params=payload.algorithm_params,
                )
            exports = app.state.service.export_enums_for_libraries(
                payload.algorithm_id,
                libraries,
                catalogs=catalogs,
                xor_value=payload.xor_value,
                algorithm_params=payload.algorithm_params,
            )
            return ExportedHeaderBatchResult(
                algorithm_id=payload.algorithm_id,
                libraries=libraries,
                exports=exports,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/bulk-auto", response_model=BulkAutoResult, summary="Bulk auto export", description="Resolve one hash then export enums for matched libraries.")
    async def bulk_auto(payload: BulkAutoRequest) -> BulkAutoResult:
        try:
            transient_catalogs = [PackLoader._catalog_record_from_payload(item) for item in (payload.catalogs or [])]
            return app.state.service.bulk_auto_export(
                hash_value=payload.hash_value,
                algorithm_id=payload.algorithm_id,
                library_names=payload.library_names,
                catalog_names=payload.catalog_names,
                catalogs=transient_catalogs,
                xor_value=payload.xor_value,
                algorithm_params=payload.algorithm_params,
                exclude_hyphenated_dlls=payload.exclude_hyphenated_dlls,
                common_windows_dlls_only=payload.common_windows_dlls_only,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/analyze-binary", summary="Analyze binary", description="Parse one binary and return imports/exports using LIEF.")
    async def analyze_binary(binary: UploadFile = File(...)):
        try:
            return app.state.service.analyze_binary(await binary.read()).model_dump(mode="json")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/validate-pack", summary="Validate pack", description="Validate pack structure and plugin/catalog files.")
    async def validate_pack(payload: ValidatePackRequest):
        return app.state.service.validate_pack(project_root / payload.pack_path).model_dump(mode="json")

    @app.post("/scaffold/algorithm", summary="Scaffold algorithm", description="Create a new algorithm scaffold file and test vectors.")
    async def scaffold(payload: ScaffoldAlgorithmRequest):
        algorithm_path, vectors_path = app.state.service.scaffold_algorithm(Path(payload.pack_path), payload.algorithm_id, payload.language)
        return {
            "algorithm_path": str(algorithm_path),
            "vectors_path": str(vectors_path),
        }

    return app
