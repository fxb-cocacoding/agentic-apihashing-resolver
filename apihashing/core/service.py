from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import math
import multiprocessing as mp
import os
from pathlib import Path
import shutil
import subprocess
import threading
from typing import Callable

from apihashing.core.analyzer import analyze_binary_blob, build_catalog_from_binary_blob, build_catalog_from_binary_path
from apihashing.core.authoring import scaffold_algorithm
from apihashing.core.models import (
    BulkAutoResult,
    CatalogRecord,
    ExportedHeaderAggregateResult,
    ExportedHeaderResult,
    HashStringAggregateResult,
    HashStringBatchResult,
    HashStringResult,
    MatchRecord,
    MergedCatalogResult,
    ResolveResult,
    SearchHashResult,
    ValidationReport,
)
from apihashing.core.pack_loader import PackLoader
from apihashing.core.renderers import render_c_header_enum
from apihashing.core.workspace import bundled_packs_root, discover_pack_roots


class ApiHashService:
    COMMON_WINDOWS_API_DLLS = {
        "advapi32.dll",
        "bcrypt.dll",
        "combase.dll",
        "crypt32.dll",
        "gdi32.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "ntdll.dll",
        "ole32.dll",
        "oleaut32.dll",
        "rpcrt4.dll",
        "shell32.dll",
        "shlwapi.dll",
        "user32.dll",
        "winhttp.dll",
        "wininet.dll",
        "ws2_32.dll",
    }

    def __init__(self, pack_roots: list[Path], project_root: Path | None = None) -> None:
        self.pack_roots = pack_roots
        self.project_root = project_root
        self.loader = PackLoader(pack_roots)
        self.packs, self.registry = self.loader.load()
        self.active_pack_names = {pack.name for pack in self.packs}
        self._runtime_lock = threading.RLock()

    @classmethod
    def from_project_root(cls, project_root: Path) -> "ApiHashService":
        pack_roots = discover_pack_roots(project_root / "packs")
        if not pack_roots:
            bundled_root = bundled_packs_root()
            if bundled_root is not None:
                pack_roots = discover_pack_roots(bundled_root)
        return cls(pack_roots=pack_roots, project_root=project_root)

    def list_algorithms(self):
        return self._active_algorithm_metadata()

    def reload_runtime(self) -> dict[str, object]:
        with self._runtime_lock:
            previous_packs = {pack.name for pack in self.packs}
            previous_active = set(self.active_pack_names)
            self._refresh_pack_roots()
            self.loader = PackLoader(self.pack_roots)
            self.packs, self.registry = self.loader.load()
            current_packs = {pack.name for pack in self.packs}
            newly_discovered = current_packs - previous_packs
            self.active_pack_names = (previous_active & current_packs) | newly_discovered
            return {
                "reloaded": True,
                "pack_count": len(self.packs),
                "active_pack_count": len(self.active_pack_names),
                "algorithm_count": len(self._active_algorithm_metadata()),
                "catalog_count": len(self.list_catalogs()),
            }

    def rebuild_native_plugins(
        self,
        pack_names: list[str] | None = None,
        target: str = "all",
    ) -> dict[str, object]:
        if shutil.which("make") is None:
            raise ValueError("`make` is not available in this runtime")
        with self._runtime_lock:
            self._refresh_pack_roots()
            requested = {name.lower() for name in (pack_names or [])}
            build_outputs: list[dict[str, str]] = []
            for pack_root in self.pack_roots:
                pack_name = pack_root.name
                if requested and pack_name.lower() not in requested:
                    continue
                native_dir = pack_root / "algorithms" / "native"
                makefile_path = native_dir / "Makefile"
                if not makefile_path.exists():
                    continue
                result = subprocess.run(
                    ["make", "-C", str(native_dir), target],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                build_outputs.append(
                    {
                        "pack": pack_name,
                        "native_dir": str(native_dir),
                        "stdout": result.stdout.strip(),
                        "stderr": result.stderr.strip(),
                    }
                )
            reload_result = self.reload_runtime()
            return {
                "rebuilt": True,
                "target": target,
                "requested_packs": pack_names or [],
                "rebuilt_packs": [item["pack"] for item in build_outputs],
                "build_outputs": build_outputs,
                "reload": reload_result,
            }

    def list_packs(self) -> list[dict[str, object]]:
        return [
            {
                "name": pack.name,
                "version": pack.version,
                "path": str(pack.root),
                "active": pack.name in self.active_pack_names,
            }
            for pack in self.packs
        ]

    def set_pack_active(self, pack_name: str, active: bool) -> dict[str, object]:
        matched = next((pack for pack in self.packs if pack.name == pack_name), None)
        if matched is None:
            raise ValueError(f"Unknown pack: {pack_name}")
        if active:
            self.active_pack_names.add(pack_name)
        else:
            self.active_pack_names.discard(pack_name)
        return next(pack for pack in self.list_packs() if pack["name"] == pack_name)

    def _active_algorithm_metadata(self):
        return [metadata for metadata in self.registry.list() if metadata.pack in self.active_pack_names]

    def _get_active_algorithm(self, algorithm_id: str):
        try:
            algorithm = self.registry.get(algorithm_id)
        except KeyError as exc:
            raise ValueError(f"Unknown algorithm: {algorithm_id}") from exc
        if algorithm.metadata.pack not in self.active_pack_names:
            raise ValueError(f"Algorithm is from inactive pack: {algorithm.metadata.id}")
        return algorithm

    def _active_algorithm_entries(self, algorithm_id: str | None = None):
        if algorithm_id is None:
            return [(metadata.id, self._get_active_algorithm(metadata.id)) for metadata in self._active_algorithm_metadata()]
        algorithm = self._get_active_algorithm(algorithm_id)
        return [(algorithm.metadata.id, algorithm)]

    def list_catalogs(
        self,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
        filter_text: str | None = None,
        sort_by: str = "name",
        sort_direction: str = "asc",
    ):
        catalogs = self._filter_catalogs(
            [catalog for pack in self.packs if pack.name in self.active_pack_names for catalog in pack.catalogs],
            exclude_hyphenated_dlls=exclude_hyphenated_dlls,
            common_windows_dlls_only=common_windows_dlls_only,
        )
        query = (filter_text or "").strip().lower()
        if query:
            catalogs = [
                catalog
                for catalog in catalogs
                if query in catalog.library.lower()
                or query in (catalog.kind or "library").lower()
                or query in (catalog.binary_family or "").lower()
            ]
        reverse = sort_direction.lower() == "desc"
        if sort_by == "type":
            catalogs = sorted(catalogs, key=lambda item: ((item.kind or "library"), item.binary_family or "", item.library.lower()), reverse=reverse)
        elif sort_by == "export_count":
            catalogs = sorted(catalogs, key=lambda item: (len(item.symbols), item.library.lower()), reverse=reverse)
        else:
            catalogs = sorted(catalogs, key=lambda item: item.library.lower(), reverse=reverse)
        return catalogs

    def get_catalogs_for_query(
        self,
        catalogs: list[CatalogRecord] | None = None,
        *,
        catalog_names: list[str] | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> list[CatalogRecord]:
        merged = self.merge_catalogs(catalogs)
        filtered = self._filter_catalogs(
            merged,
            exclude_hyphenated_dlls=exclude_hyphenated_dlls,
            common_windows_dlls_only=common_windows_dlls_only,
        )
        if not catalog_names:
            return filtered
        allowed = {name.lower() for name in catalog_names}
        return [catalog for catalog in filtered if catalog.library.lower() in allowed]

    def merge_catalogs(self, catalogs: list[CatalogRecord] | None = None) -> list[CatalogRecord]:
        active_catalogs = [catalog for pack in self.packs if pack.name in self.active_pack_names for catalog in pack.catalogs]
        merged = self._merge_catalog_records(active_catalogs)
        # Transient catalogs override same-named active catalogs for the current request.
        merged.update(self._merge_catalog_records(catalogs or []))
        return list(merged.values())

    def resolve_hash(
        self,
        hash_value: int | str,
        algorithm_id: str,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
        library_names: list[str] | None = None,
        catalog_names: list[str] | None = None,
        catalogs: list[CatalogRecord] | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> ResolveResult:
        algorithm = self._get_active_algorithm(algorithm_id)
        query_input = str(hash_value)
        query_unsigned_int = self._parse_hash_value(hash_value)
        xor_unsigned_int = self._parse_hash_value(xor_value) if xor_value is not None else 0
        query_unsigned_int ^= xor_unsigned_int
        normalized_params, base_values = self._normalize_base_values(algorithm_params)
        selected_catalogs = self.get_catalogs_for_query(
            catalogs,
            catalog_names=catalog_names,
            exclude_hyphenated_dlls=exclude_hyphenated_dlls,
            common_windows_dlls_only=common_windows_dlls_only,
        )
        matches: list[MatchRecord] = []
        for base_value in base_values:
            params_for_run = dict(normalized_params)
            if base_value is not None:
                params_for_run["base"] = base_value
            matches.extend(
                self._collect_matches_for_algorithm(
                    algorithm_id,
                    algorithm,
                    query_unsigned_int,
                    library_names=library_names,
                    catalogs=selected_catalogs,
                    algorithm_params=params_for_run,
                    base_value=base_value,
                )
            )
        query_hex = self._to_query_hex(query_unsigned_int)
        return ResolveResult(
            algorithm_id=algorithm_id,
            query_hash_input=query_input,
            query_hash_unsigned_int=query_unsigned_int,
            query_hash_hex=query_hex,
            matches=matches,
        )

    def search_hash_across_algorithms(
        self,
        hash_value: int | str,
        algorithm_id: str | None = None,
        library_filter: str | None = None,
        library_names: list[str] | None = None,
        catalog_names: list[str] | None = None,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> SearchHashResult:
        effective_exclude_hyphenated_dlls = exclude_hyphenated_dlls
        effective_common_windows_dlls_only = common_windows_dlls_only
        broad_unscoped_search = (
            not algorithm_id
            and not library_filter
            and not library_names
            and not catalog_names
            and not exclude_hyphenated_dlls
            and not common_windows_dlls_only
        )
        if (
            broad_unscoped_search
        ):
            effective_common_windows_dlls_only = True

        if self._should_use_parallel_algorithm_search(
            catalog_names=catalog_names,
            algorithm_params=algorithm_params,
            algorithm_id=algorithm_id,
        ):
            try:
                return self._search_hash_across_algorithms_parallel(
                    hash_value=hash_value,
                    algorithm_id=algorithm_id,
                    library_filter=library_filter,
                    library_names=library_names,
                    catalog_names=catalog_names,
                    xor_value=xor_value,
                    algorithm_params=algorithm_params,
                    exclude_hyphenated_dlls=effective_exclude_hyphenated_dlls,
                    common_windows_dlls_only=effective_common_windows_dlls_only,
                )
            except Exception:
                pass

        return self.search_hash_in_catalogs(
            hash_value,
            self.get_catalogs_for_query(
                catalog_names=catalog_names,
                exclude_hyphenated_dlls=effective_exclude_hyphenated_dlls,
                common_windows_dlls_only=effective_common_windows_dlls_only,
            ),
            library_filter,
            algorithm_id=algorithm_id,
            library_names=library_names,
            xor_value=xor_value,
            algorithm_params=algorithm_params,
            exclude_hyphenated_dlls=effective_exclude_hyphenated_dlls,
            common_windows_dlls_only=effective_common_windows_dlls_only,
            max_matches_per_algorithm=1 if broad_unscoped_search else None,
        )

    def _should_use_parallel_algorithm_search(
        self,
        *,
        catalog_names: list[str] | None,
        algorithm_params: dict[str, object] | None,
        algorithm_id: str | None,
    ) -> bool:
        if not self._env_flag("APIHASHING_ENABLE_MP_SEARCH", default=True):
            return False
        if self.project_root is None:
            return False
        if algorithm_id:
            return False
        if algorithm_params:
            return False
        if catalog_names:
            return False
        try:
            mp.get_context("fork")
        except ValueError:
            return False
        return True

    def _search_hash_across_algorithms_parallel(
        self,
        *,
        hash_value: int | str,
        algorithm_id: str | None,
        library_filter: str | None,
        library_names: list[str] | None,
        catalog_names: list[str] | None,
        xor_value: int | str | None,
        algorithm_params: dict[str, object] | None,
        exclude_hyphenated_dlls: bool,
        common_windows_dlls_only: bool,
    ) -> SearchHashResult:
        query_unsigned_int = self._parse_hash_value(hash_value)
        xor_unsigned_int = self._parse_hash_value(xor_value) if xor_value is not None else 0
        query_unsigned_int ^= xor_unsigned_int
        normalized_params, base_values = self._normalize_base_values(algorithm_params)

        algorithm_ids = [entry_id for entry_id, _ in self._active_algorithm_entries(algorithm_id)]
        worker_count = self._process_pool_worker_count(len(algorithm_ids))
        if worker_count <= 1:
            return self.search_hash_in_catalogs(
                hash_value=hash_value,
                catalogs=self.get_catalogs_for_query(
                    catalog_names=catalog_names,
                    exclude_hyphenated_dlls=exclude_hyphenated_dlls,
                    common_windows_dlls_only=common_windows_dlls_only,
                ),
                library_filter=library_filter,
                algorithm_id=algorithm_id,
                library_names=library_names,
                xor_value=xor_value,
                algorithm_params=algorithm_params,
                exclude_hyphenated_dlls=exclude_hyphenated_dlls,
                common_windows_dlls_only=common_windows_dlls_only,
            )

        chunk_size = max(1, math.ceil(len(algorithm_ids) / worker_count))
        algorithm_chunks = [algorithm_ids[index: index + chunk_size] for index in range(0, len(algorithm_ids), chunk_size)]
        task = {
            "query_unsigned_int": query_unsigned_int,
            "library_filter": library_filter,
            "library_names": library_names,
            "algorithm_params": normalized_params,
            "base_values": base_values,
        }
        ctx = mp.get_context("fork")
        with ctx.Pool(
            processes=worker_count,
            initializer=_parallel_search_worker_init,
            initargs=(
                str(self.project_root),
                sorted(self.active_pack_names),
                catalog_names or [],
                exclude_hyphenated_dlls,
                common_windows_dlls_only,
            ),
        ) as pool:
            nested_payloads = pool.map(
                _parallel_search_worker_run,
                [{"algorithm_ids": chunk, **task} for chunk in algorithm_chunks],
            )

        matches = [MatchRecord.model_validate(item) for items in nested_payloads for item in items]
        return SearchHashResult(
            query_hash_input=str(hash_value),
            query_hash_unsigned_int=query_unsigned_int,
            query_hash_hex=self._to_query_hex(query_unsigned_int),
            library_filter=library_filter,
            execution_mode="process_pool",
            worker_count=worker_count,
            algorithm_count=len(algorithm_ids),
            results=matches,
        )

    def search_hash_in_catalogs(
        self,
        hash_value: int | str,
        catalogs: list[CatalogRecord],
        library_filter: str | None = None,
        algorithm_id: str | None = None,
        library_names: list[str] | None = None,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
        max_matches_per_algorithm: int | None = None,
    ) -> SearchHashResult:
        query_unsigned_int = self._parse_hash_value(hash_value)
        xor_unsigned_int = self._parse_hash_value(xor_value) if xor_value is not None else 0
        query_unsigned_int ^= xor_unsigned_int
        normalized_params, base_values = self._normalize_base_values(algorithm_params)
        filtered_catalogs = self._filter_catalogs(
            catalogs,
            exclude_hyphenated_dlls=exclude_hyphenated_dlls,
            common_windows_dlls_only=common_windows_dlls_only,
        )
        algorithm_entries = self._active_algorithm_entries(algorithm_id)
        worker_count = self._threadpool_worker_count(
            len(algorithm_entries),
            env_var_name="APIHASHING_SEARCH_MAX_WORKERS",
        )

        if worker_count > 1:
            ordered_results: list[list[MatchRecord]] = [[] for _ in algorithm_entries]
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = {
                    executor.submit(
                        self._collect_matches_for_algorithm_over_bases,
                        algorithm_id,
                        loaded,
                        query_unsigned_int,
                        library_filter,
                        library_names,
                        filtered_catalogs,
                        normalized_params,
                        base_values,
                        max_matches_per_algorithm,
                    ): index
                    for index, (algorithm_id, loaded) in enumerate(algorithm_entries)
                }
                for future in as_completed(futures):
                    ordered_results[futures[future]] = future.result()
            results = [item for group in ordered_results for item in group]
        else:
            results = []
            for algorithm_id, loaded in algorithm_entries:
                results.extend(
                    self._collect_matches_for_algorithm_over_bases(
                        algorithm_id,
                        loaded,
                        query_unsigned_int,
                        library_filter,
                        library_names,
                        filtered_catalogs,
                        normalized_params,
                        base_values,
                        max_matches_per_algorithm,
                    )
                )
        return SearchHashResult(
            query_hash_input=str(hash_value),
            query_hash_unsigned_int=query_unsigned_int,
            query_hash_hex=self._to_query_hex(query_unsigned_int),
            library_filter=library_filter,
            execution_mode="threadpool" if worker_count > 1 else "single_thread",
            worker_count=worker_count,
            algorithm_count=len(algorithm_entries),
            results=results,
        )

    def _collect_matches_for_algorithm_over_bases(
        self,
        algorithm_id: str,
        algorithm,
        query_unsigned_int: int,
        library_filter: str | None,
        library_names: list[str] | None,
        catalogs: list[CatalogRecord],
        normalized_params: dict[str, object],
        base_values: list[int | None],
        max_matches_per_algorithm: int | None,
    ) -> list[MatchRecord]:
        matches: list[MatchRecord] = []
        for base_value in base_values:
            params_for_run = dict(normalized_params)
            if base_value is not None:
                params_for_run["base"] = base_value
            max_matches = None
            if max_matches_per_algorithm is not None:
                remaining = max_matches_per_algorithm - len(matches)
                if remaining <= 0:
                    break
                max_matches = remaining
            matches.extend(
                self._collect_matches_for_algorithm(
                    algorithm_id,
                    algorithm,
                    query_unsigned_int,
                    library_filter,
                    library_names,
                    catalogs,
                    algorithm_params=params_for_run,
                    base_value=base_value,
                    max_matches=max_matches,
                )
            )
        return matches

    def library_matches_scope(
        self,
        library_name: str,
        *,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> bool:
        normalized = library_name.lower()
        if (exclude_hyphenated_dlls or common_windows_dlls_only) and "-" in normalized:
            return False
        if common_windows_dlls_only and normalized not in self.COMMON_WINDOWS_API_DLLS:
            return False
        return True

    def hash_string_for_algorithm(
        self,
        algorithm_id: str,
        symbol_name: str,
        library_name: str = "",
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
    ) -> HashStringResult | HashStringAggregateResult:
        algorithm = self._get_active_algorithm(algorithm_id)
        normalized_params, base_values = self._normalize_base_values(algorithm_params)
        results = self._hash_string_results_for_base_values(
            algorithm_id=algorithm_id,
            algorithm=algorithm,
            symbol_name=symbol_name,
            library_name=library_name,
            xor_value=xor_value,
            algorithm_params=normalized_params,
            base_values=base_values,
        )
        if len(results) == 1:
            return results[0]
        return HashStringAggregateResult(
            algorithm_id=algorithm_id,
            library_name=library_name,
            symbol_name=symbol_name,
            results=results,
        )

    def hash_string_for_libraries(
        self,
        algorithm_id: str,
        symbol_name: str,
        library_names: list[str] | None = None,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
    ) -> HashStringBatchResult:
        libraries = library_names or [""]
        normalized_params, base_values = self._normalize_base_values(algorithm_params)
        algorithm = self._get_active_algorithm(algorithm_id)
        results = []
        for library_name in libraries:
            results.extend(
                self._hash_string_results_for_base_values(
                    algorithm_id=algorithm_id,
                    algorithm=algorithm,
                    symbol_name=symbol_name,
                    library_name=library_name,
                    xor_value=xor_value,
                    algorithm_params=normalized_params,
                    base_values=base_values,
                )
            )
        if len({name.lower() for name in libraries if name}) > 1:
            results = self._collapse_library_insensitive_hash_results(results)
        return HashStringBatchResult(
            algorithm_id=algorithm_id,
            libraries=libraries,
            symbol_name=symbol_name,
            results=results,
        )

    def hash_string_for_catalogs(
        self,
        algorithm_id: str,
        symbol_name: str,
        catalogs: list[CatalogRecord],
        library_names: list[str] | None = None,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
    ) -> HashStringBatchResult:
        normalized_params, base_values = self._normalize_base_values(algorithm_params)
        algorithm = self._get_active_algorithm(algorithm_id)
        results = []
        libraries = [catalog.library for catalog in catalogs]
        allowed_libraries = {name.lower() for name in (library_names or [])}
        selected_catalogs = [catalog for catalog in catalogs if not allowed_libraries or catalog.library.lower() in allowed_libraries]
        for catalog in selected_catalogs:
            library_name = catalog.library if catalog.kind != "wordlist" else ""
            results.extend(
                self._hash_string_results_for_base_values(
                    algorithm_id=algorithm_id,
                    algorithm=algorithm,
                    symbol_name=symbol_name,
                    library_name=library_name,
                    xor_value=xor_value,
                    algorithm_params=normalized_params,
                    base_values=base_values,
                )
            )
        if len({catalog.library.lower() for catalog in selected_catalogs if catalog.kind != "wordlist"}) > 1:
            results = self._collapse_library_insensitive_hash_results(results)
        return HashStringBatchResult(
            algorithm_id=algorithm_id,
            libraries=[catalog.library for catalog in selected_catalogs],
            symbol_name=symbol_name,
            results=results,
        )

    def build_catalogs_from_binaries(self, binaries: list[tuple[str, bytes]]) -> MergedCatalogResult:
        libraries = [
            catalog
            for filename, blob in binaries
            if (catalog := build_catalog_from_binary_blob(filename, blob)).symbols
            and self._catalog_allowed_for_build(catalog, filename)
        ]
        if not libraries:
            raise ValueError("No parseable library files with exports found in the provided inputs")
        return MergedCatalogResult(libraries=libraries)

    def build_catalogs_from_paths(
        self,
        paths: list[Path],
        progress_callback: Callable[[int, int, Path], None] | None = None,
        max_workers: int | None = None,
    ) -> MergedCatalogResult:
        libraries: list[CatalogRecord] = []
        binary_paths = self._iter_binary_paths(paths)
        total = len(binary_paths)
        if total == 0:
            raise ValueError("No parseable library files found in the provided paths")
        worker_count = max_workers or min(32, (os.cpu_count() or 1) + 4)
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {executor.submit(build_catalog_from_binary_path, binary_path): binary_path for binary_path in binary_paths}
            for future in as_completed(futures):
                binary_path = futures[future]
                completed += 1
                if progress_callback is not None:
                    progress_callback(completed, total, binary_path)
                try:
                    catalog = future.result()
                    if catalog.symbols and self._catalog_allowed_for_build(catalog, binary_path.name):
                        libraries.append(catalog)
                except Exception:
                    continue
        if not libraries:
            raise ValueError("No parseable library files with exports found in the provided paths")
        return MergedCatalogResult(libraries=libraries)

    @staticmethod
    def _catalog_allowed_for_build(catalog: CatalogRecord, source_name: str) -> bool:
        # For PE files, keep only DLL inputs. ELF and Mach-O behavior remains unchanged.
        if catalog.binary_family != "pe":
            return True
        return Path(source_name).suffix.lower() == ".dll"

    def export_enum_for_library(
        self,
        algorithm_id: str,
        library_name: str,
        catalogs: list[CatalogRecord] | None = None,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
    ) -> ExportedHeaderResult | ExportedHeaderAggregateResult:
        catalog = self._find_catalog_by_library(library_name, catalogs or self.list_catalogs())
        algorithm = self._get_active_algorithm(algorithm_id)
        xor_unsigned_int = self._parse_hash_value(xor_value) if xor_value is not None else 0
        normalized_params, base_values = self._normalize_base_values(algorithm_params)
        results = self._export_enum_results_for_base_values(
            algorithm_id=algorithm_id,
            algorithm=algorithm,
            catalog=catalog,
            xor_value=xor_unsigned_int,
            algorithm_params=normalized_params,
            base_values=base_values,
        )
        if len(results) == 1:
            return results[0]
        return ExportedHeaderAggregateResult(
            algorithm_id=algorithm_id,
            library_name=library_name,
            results=results,
        )

    def export_enums_for_libraries(
        self,
        algorithm_id: str,
        library_names: list[str],
        catalogs: list[CatalogRecord] | None = None,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
    ) -> list[ExportedHeaderResult]:
        normalized_params, base_values = self._normalize_base_values(algorithm_params)
        algorithm = self._get_active_algorithm(algorithm_id)
        catalog_source = catalogs or self.list_catalogs()
        xor_unsigned_int = self._parse_hash_value(xor_value) if xor_value is not None else 0
        library_jobs = [(index, library_name, self._find_catalog_by_library(library_name, catalog_source)) for index, library_name in enumerate(library_names)]

        worker_count = self._threadpool_worker_count(
            len(library_jobs),
            env_var_name="APIHASHING_EXPORT_MAX_WORKERS",
        )
        if worker_count <= 1:
            results: list[ExportedHeaderResult] = []
            for _, _, catalog in library_jobs:
                results.extend(
                    self._export_enum_results_for_base_values(
                        algorithm_id=algorithm_id,
                        algorithm=algorithm,
                        catalog=catalog,
                        xor_value=xor_unsigned_int,
                        algorithm_params=normalized_params,
                        base_values=base_values,
                    )
                )
            return results

        ordered_results: list[list[ExportedHeaderResult]] = [[] for _ in library_jobs]
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    self._export_enum_results_for_base_values,
                    algorithm_id=algorithm_id,
                    algorithm=algorithm,
                    catalog=catalog,
                    xor_value=xor_unsigned_int,
                    algorithm_params=normalized_params,
                    base_values=base_values,
                ): index
                for index, _, catalog in library_jobs
            }
            for future in as_completed(futures):
                ordered_results[futures[future]] = future.result()
        return [item for group in ordered_results for item in group]

    def bulk_auto_export(
        self,
        hash_value: int | str,
        algorithm_id: str,
        library_names: list[str] | None = None,
        catalog_names: list[str] | None = None,
        catalogs: list[CatalogRecord] | None = None,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> BulkAutoResult:
        selected_catalogs = self.get_catalogs_for_query(
            catalogs,
            catalog_names=catalog_names,
            exclude_hyphenated_dlls=exclude_hyphenated_dlls,
            common_windows_dlls_only=common_windows_dlls_only,
        )
        query_value = self._parse_hash_value(hash_value)
        xor_unsigned_int = self._parse_hash_value(xor_value) if xor_value is not None else 0
        if xor_unsigned_int:
            query_value ^= xor_unsigned_int
        result = self.resolve_hash(
            query_value,
            algorithm_id,
            xor_value=None,
            algorithm_params=algorithm_params,
            library_names=library_names,
            catalog_names=catalog_names,
            catalogs=selected_catalogs,
            exclude_hyphenated_dlls=exclude_hyphenated_dlls,
            common_windows_dlls_only=common_windows_dlls_only,
        )
        matched_libraries = []
        seen: set[tuple[str, int | None]] = set()
        for match in result.matches:
            key = (match.library.lower(), match.base_value)
            if key in seen:
                continue
            seen.add(key)
            matched_libraries.append((match.library, match.base_value))
        normalized_params = self._normalize_algorithm_params(algorithm_params)
        exports = []
        for library_name, base_value in matched_libraries:
            params_for_run = dict(normalized_params)
            params_for_run.pop("base_values", None)
            if base_value is not None:
                params_for_run["base"] = base_value
            exports.append(
                self.export_enum_for_library(
                    algorithm_id,
                    library_name,
                    catalogs=selected_catalogs,
                    xor_value=xor_value,
                    algorithm_params=params_for_run,
                )
            )
        return BulkAutoResult(
            algorithm_id=algorithm_id,
            query_hash_input=str(hash_value),
            query_hash_unsigned_int=result.query_hash_unsigned_int,
            query_hash_hex=result.query_hash_hex,
            matches=result.matches,
            exports=exports,
        )

    def list_hashdb_algorithms(self) -> list[dict[str, str]]:
        algorithms = []
        for metadata in self._active_algorithm_metadata():
            hash_type = "unknown"
            if metadata.hash_size_bits == 32:
                hash_type = "unsigned_int"
            elif metadata.hash_size_bits == 64:
                hash_type = "unsigned_long"
            algorithms.append(
                {
                    "algorithm": metadata.id,
                    "type": hash_type,
                    "description": metadata.description,
                    "source": metadata.source or "",
                    "license": metadata.license or "",
                }
            )
        return algorithms

    def hashdb_lookup(
        self,
        algorithm_id: str,
        hash_value: int | str,
        xor_value: int | str | None = None,
        algorithm_params: dict[str, object] | None = None,
    ) -> dict[str, list[dict[str, object]]]:
        result = self.resolve_hash(
            hash_value=hash_value,
            algorithm_id=algorithm_id,
            xor_value=xor_value,
            algorithm_params=algorithm_params,
        )
        hashes = []
        for item in result.matches:
            hashes.append(
                {
                    "hash": item.hash_value_unsigned_int,
                    "string": {
                        "is_api": True,
                        "api": item.symbol,
                        "module": item.library,
                        "modules": [item.library],
                        "permutation": "",
                    },
                }
            )
        return {"hashes": hashes}

    def hashdb_module_hashes(
        self,
        module_name: str,
        algorithm_id: str,
        permutation: str = "",
        xor_value: int | str | None = None,
        catalogs: list[CatalogRecord] | None = None,
        algorithm_params: dict[str, object] | None = None,
    ) -> dict[str, list[dict[str, object]]]:
        # Keep module hashes raw for HashDB-IDA drop-in compatibility.
        # The client applies XOR locally when that option is enabled.
        _ = xor_value
        catalog = self._find_catalog_by_library(module_name, catalogs or self.list_catalogs())
        algorithm = self._get_active_algorithm(algorithm_id)
        normalized_params = self._normalize_algorithm_params(algorithm_params)
        hashes = []
        for symbol in catalog.symbols:
            computed = algorithm.compute(catalog.library, symbol, normalized_params)
            value = computed.to_unsigned_int()
            hashes.append(
                {
                    "hash": value,
                    "string": {
                        "is_api": True,
                        "api": symbol,
                        "module": catalog.library,
                        "modules": [catalog.library],
                        "permutation": permutation,
                    },
                }
            )
        return {"hashes": hashes}

    def hashdb_hunt(self, hashes: list[int | str], xor_value: int | str | None = None) -> dict[str, list[dict[str, object]]]:
        hits: list[dict[str, object]] = []
        seen: set[str] = set()
        for value in hashes:
            result = self.search_hash_across_algorithms(value, xor_value=xor_value)
            for item in result.results:
                if item.algorithm_id in seen:
                    continue
                seen.add(item.algorithm_id)
                hits.append({"algorithm": item.algorithm_id})
        return {"hits": hits}

    def analyze_binary(self, blob: bytes):
        return analyze_binary_blob(blob)

    def validate_pack(self, pack_path: Path) -> ValidationReport:
        return self.loader.validate(pack_path)

    def scaffold_algorithm(self, pack_path: Path, algorithm_id: str, language: str) -> tuple[Path, Path]:
        return scaffold_algorithm(pack_path, algorithm_id, language)

    def _collect_matches_for_algorithm(
        self,
        algorithm_id: str,
        algorithm,
        query_unsigned_int: int,
        library_filter: str | None = None,
        library_names: list[str] | None = None,
        catalogs: list[CatalogRecord] | None = None,
        algorithm_params: dict[str, object] | None = None,
        base_value: int | None = None,
        max_matches: int | None = None,
    ) -> list[MatchRecord]:
        matches: list[MatchRecord] = []
        normalized_filter = library_filter.lower() if library_filter else None
        normalized_names = {name.lower() for name in (library_names or [])}
        catalog_source = catalogs or self.list_catalogs()
        pack_by_library = {catalog.library: pack.name for pack in self.packs for catalog in pack.catalogs}
        for catalog in catalog_source:
            if normalized_filter and normalized_filter not in catalog.library.lower():
                continue
            if normalized_names and catalog.library.lower() not in normalized_names:
                continue
            library_input = catalog.library if catalog.kind != "wordlist" else ""
            for symbol in catalog.symbols:
                try:
                    computed = algorithm.compute(library_input, symbol, algorithm_params)
                except Exception:
                    continue
                if computed.to_unsigned_int() == query_unsigned_int:
                    matches.append(
                        MatchRecord(
                            pack=pack_by_library.get(catalog.library, "external"),
                            algorithm_id=algorithm_id,
                            library=catalog.library,
                            symbol=symbol,
                            base_value=base_value,
                            catalog_kind=catalog.kind or "library",
                            binary_family=catalog.binary_family,
                            hash_size_bits=computed.bit_length,
                            hash_value_unsigned_int=computed.to_unsigned_int(),
                            hash_value_hex=computed.to_hex(),
                        )
                    )
                    if max_matches is not None and len(matches) >= max_matches:
                        return matches
        return matches

    def _hash_string_for_algorithm_single(
        self,
        *,
        algorithm_id: str,
        algorithm,
        symbol_name: str,
        library_name: str,
        xor_value: int | str | None,
        algorithm_params: dict[str, object],
        base_value: int | None,
    ) -> HashStringResult:
        computed = algorithm.compute(library_name, symbol_name, algorithm_params)
        xor_unsigned_int = self._parse_hash_value(xor_value) if xor_value is not None else 0
        if xor_unsigned_int:
            computed = computed.__class__.from_int(
                computed.to_unsigned_int() ^ xor_unsigned_int,
                bit_length=computed.bit_length,
            )
        return HashStringResult(
            algorithm_id=algorithm_id,
            library_name=library_name,
            symbol_name=symbol_name,
            base_value=base_value,
            hash_size_bits=computed.bit_length,
            hash_value_unsigned_int=computed.to_unsigned_int(),
            hash_value_hex=computed.to_hex(),
        )

    def _hash_string_results_for_base_values(
        self,
        *,
        algorithm_id: str,
        algorithm,
        symbol_name: str,
        library_name: str,
        xor_value: int | str | None,
        algorithm_params: dict[str, object],
        base_values: list[int | None],
    ) -> list[HashStringResult]:
        results: list[HashStringResult] = []
        for base_value in base_values:
            params_for_run = dict(algorithm_params)
            if base_value is not None:
                params_for_run["base"] = base_value
            results.append(
                self._hash_string_for_algorithm_single(
                    algorithm_id=algorithm_id,
                    algorithm=algorithm,
                    symbol_name=symbol_name,
                    library_name=library_name,
                    xor_value=xor_value,
                    algorithm_params=params_for_run,
                    base_value=base_value,
                )
            )
        return results

    @staticmethod
    def _collapse_library_insensitive_hash_results(results: list[HashStringResult]) -> list[HashStringResult]:
        grouped: dict[tuple[str, int | None, int | None, int], tuple[HashStringResult, set[str]]] = {}
        order: list[tuple[str, int | None, int | None, int]] = []
        for item in results:
            key = (
                item.symbol_name,
                item.base_value,
                item.hash_size_bits,
                item.hash_value_unsigned_int,
            )
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = (item, {item.library_name.lower()})
                order.append(key)
                continue
            first, libraries = existing
            libraries.add(item.library_name.lower())
            grouped[key] = (first, libraries)

        deduped: list[HashStringResult] = []
        for key in order:
            item, libraries = grouped[key]
            collapsed_library_name = "" if len({library for library in libraries if library}) > 1 else item.library_name
            deduped.append(
                HashStringResult(
                    algorithm_id=item.algorithm_id,
                    library_name=collapsed_library_name,
                    symbol_name=item.symbol_name,
                    base_value=item.base_value,
                    hash_size_bits=item.hash_size_bits,
                    hash_value_unsigned_int=item.hash_value_unsigned_int,
                    hash_value_hex=item.hash_value_hex,
                )
            )
        return deduped

    def _export_enum_for_library_single(
        self,
        *,
        algorithm_id: str,
        algorithm,
        catalog: CatalogRecord,
        xor_value: int,
        algorithm_params: dict[str, object],
        base_value: int | None,
    ) -> ExportedHeaderResult:
        entries = []
        for symbol in catalog.symbols:
            value = algorithm.compute(catalog.library, symbol, algorithm_params)
            if xor_value:
                value = value.__class__.from_int(value.to_unsigned_int() ^ xor_value, bit_length=value.bit_length)
            entries.append((symbol, value))
        result = render_c_header_enum(
            algorithm_id=algorithm_id,
            catalog=catalog,
            entries=entries,
            hash_size_bits=algorithm.metadata.hash_size_bits,
        )
        result.base_value = base_value
        return result

    def _export_enum_results_for_base_values(
        self,
        *,
        algorithm_id: str,
        algorithm,
        catalog: CatalogRecord,
        xor_value: int,
        algorithm_params: dict[str, object],
        base_values: list[int | None],
    ) -> list[ExportedHeaderResult]:
        results: list[ExportedHeaderResult] = []
        for base_value in base_values:
            params_for_run = dict(algorithm_params)
            if base_value is not None:
                params_for_run["base"] = base_value
            results.append(
                self._export_enum_for_library_single(
                    algorithm_id=algorithm_id,
                    algorithm=algorithm,
                    catalog=catalog,
                    xor_value=xor_value,
                    algorithm_params=params_for_run,
                    base_value=base_value,
                )
            )
        return results

    def _filter_catalogs(
        self,
        catalogs: list[CatalogRecord],
        *,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> list[CatalogRecord]:
        if not exclude_hyphenated_dlls and not common_windows_dlls_only:
            return catalogs
        return [
            catalog
            for catalog in catalogs
            if catalog.kind == "wordlist"
            or self.library_matches_scope(
                catalog.library,
                exclude_hyphenated_dlls=exclude_hyphenated_dlls,
                common_windows_dlls_only=common_windows_dlls_only,
            )
        ]

    @classmethod
    def _normalize_algorithm_params(cls, algorithm_params: dict[str, object] | None) -> dict[str, object]:
        normalized: dict[str, object] = {}
        for key, value in (algorithm_params or {}).items():
            if isinstance(value, str):
                normalized[key] = value.strip()
                continue
            normalized[key] = value
        return normalized

    @staticmethod
    def _merge_catalog_records(catalogs: list[CatalogRecord]) -> dict[tuple[str, str], CatalogRecord]:
        merged: dict[tuple[str, str], CatalogRecord] = {}
        for catalog in catalogs:
            key = ((catalog.kind or "library"), catalog.library.lower())
            existing = merged.get(key)
            if existing is None:
                merged[key] = CatalogRecord(
                    kind=catalog.kind,
                    binary_family=catalog.binary_family,
                    library=catalog.library,
                    symbols=sorted(set(catalog.symbols)),
                    source_path=catalog.source_path,
                )
                continue
            existing.symbols = sorted(set([*existing.symbols, *catalog.symbols]))
        return merged

    @classmethod
    def _normalize_base_values(
        cls,
        algorithm_params: dict[str, object] | None,
    ) -> tuple[dict[str, object], list[int | None]]:
        normalized = cls._normalize_algorithm_params(algorithm_params)
        raw_values = normalized.pop("base_values", None)
        raw_single = normalized.get("base")
        if raw_values is not None and raw_single is not None:
            raise ValueError("algorithm_params cannot contain both base and base_values")
        if raw_values is None and raw_single is not None:
            raw_values = [raw_single]
        if raw_values is None:
            return normalized, [None]
        if not isinstance(raw_values, list):
            raw_values = [raw_values]
        seen: set[int] = set()
        base_values: list[int] = []
        for item in raw_values:
            parsed = cls._parse_hash_value(item)
            if parsed in seen:
                continue
            seen.add(parsed)
            base_values.append(parsed)
        return normalized, base_values or [None]

    @staticmethod
    def _iter_binary_paths(paths: list[Path]) -> list[Path]:
        discovered: list[Path] = []
        for path in paths:
            if path.is_dir():
                discovered.extend(sorted(candidate for candidate in path.rglob("*") if candidate.is_file()))
            elif path.is_file():
                discovered.append(path)
        return discovered

    def _refresh_pack_roots(self) -> None:
        if self.project_root is None:
            return
        pack_roots = discover_pack_roots(self.project_root / "packs")
        if not pack_roots:
            bundled_root = bundled_packs_root()
            if bundled_root is not None:
                pack_roots = discover_pack_roots(bundled_root)
        self.pack_roots = pack_roots

    @staticmethod
    def _find_catalog_by_library(library_name: str, catalogs: list[CatalogRecord]) -> CatalogRecord:
        normalized = library_name.lower()
        for catalog in catalogs:
            if catalog.kind != "wordlist" and catalog.library.lower() == normalized:
                return catalog
        raise ValueError(f"Library not found in loaded catalogs: {library_name}")

    @staticmethod
    def _parse_hash_value(hash_value: int | str) -> int:
        if isinstance(hash_value, int):
            return hash_value
        value = hash_value.strip().lower()
        if value.startswith("0x"):
            return int(value, 16)
        if value.endswith("h"):
            hex_value = value[:-1].strip()
            if not hex_value:
                raise ValueError("Invalid IDA-style hex value")
            return int(hex_value, 16)
        if all(ch in "0123456789abcdef" for ch in value) and any(ch.isalpha() for ch in value):
            return int(value, 16)
        return int(value, 10)

    @staticmethod
    def _to_query_hex(hash_value: int) -> str:
        if hash_value == 0:
            return "00"
        width = max((hash_value.bit_length() + 7) // 8, 1)
        return hash_value.to_bytes(width, "big").hex()

    @staticmethod
    def _threadpool_worker_count(total_items: int, *, env_var_name: str) -> int:
        if total_items <= 0:
            return 0
        configured_workers = max(1, os.cpu_count() or 1)
        raw = (os.environ.get(env_var_name) or "").strip()
        if raw:
            try:
                configured_workers = max(1, int(raw))
            except ValueError:
                configured_workers = max(1, os.cpu_count() or 1)
        return configured_workers

    @staticmethod
    def _process_pool_worker_count(total_items: int) -> int:
        if total_items <= 0:
            return 0
        default_workers = max(1, os.cpu_count() or 1)
        raw = (os.environ.get("APIHASHING_MP_SEARCH_MAX_WORKERS") or "").strip()
        if raw:
            try:
                default_workers = max(1, int(raw))
            except ValueError:
                default_workers = max(1, os.cpu_count() or 1)
        return default_workers

    @staticmethod
    def _env_flag(name: str, *, default: bool) -> bool:
        raw = os.environ.get(name)
        if raw is None:
            return default
        value = raw.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        return default


_PARALLEL_SEARCH_SERVICE: ApiHashService | None = None
_PARALLEL_SEARCH_CATALOGS: list[CatalogRecord] = []


def _parallel_search_worker_init(
    project_root: str,
    active_pack_names: list[str],
    catalog_names: list[str],
    exclude_hyphenated_dlls: bool,
    common_windows_dlls_only: bool,
) -> None:
    global _PARALLEL_SEARCH_SERVICE, _PARALLEL_SEARCH_CATALOGS
    service = ApiHashService.from_project_root(Path(project_root))
    service.active_pack_names = set(active_pack_names)
    _PARALLEL_SEARCH_SERVICE = service
    _PARALLEL_SEARCH_CATALOGS = service.get_catalogs_for_query(
        catalog_names=catalog_names or None,
        exclude_hyphenated_dlls=exclude_hyphenated_dlls,
        common_windows_dlls_only=common_windows_dlls_only,
    )


def _parallel_search_worker_run(payload: dict[str, object]) -> list[dict[str, object]]:
    service = _PARALLEL_SEARCH_SERVICE
    if service is None:
        return []
    query_unsigned_int = int(payload["query_unsigned_int"])
    library_filter = payload.get("library_filter")
    library_names = payload.get("library_names")
    algorithm_params = dict(payload.get("algorithm_params") or {})
    base_values = list(payload.get("base_values") or [None])
    algorithm_ids = list(payload.get("algorithm_ids") or [])

    matches: list[MatchRecord] = []
    for algorithm_id in algorithm_ids:
        loaded = service._get_active_algorithm(str(algorithm_id))
        for base_value in base_values:
            params_for_run = dict(algorithm_params)
            if base_value is not None:
                params_for_run["base"] = int(base_value)
            matches.extend(
                service._collect_matches_for_algorithm(
                    str(algorithm_id),
                    loaded,
                    query_unsigned_int,
                    str(library_filter) if library_filter is not None else None,
                    list(library_names or []),
                    _PARALLEL_SEARCH_CATALOGS,
                    algorithm_params=params_for_run,
                    base_value=int(base_value) if base_value is not None else None,
                )
            )
    return [match.model_dump(mode="json", exclude_none=True) for match in matches]
