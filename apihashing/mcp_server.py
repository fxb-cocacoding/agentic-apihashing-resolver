from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from contextlib import ExitStack
from glob import glob
from pathlib import Path
from typing import Any

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _ensure_mcp_on_path() -> None:
    try:
        import mcp  # noqa: F401
        return
    except Exception:
        pass

    candidates: list[str] = []
    env_path = os.environ.get("APIHASHING_MCP_PYTHONPATH", "").strip()
    if env_path:
        candidates.append(env_path)
    candidates.extend(sorted(glob("/home/fxb/opt/ghidra/venv/lib/python*/site-packages")))

    for candidate in candidates:
        if candidate and candidate not in sys.path and Path(candidate).exists():
            sys.path.insert(0, candidate)

    import mcp  # noqa: F401


_ensure_mcp_on_path()

from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.server.lowlevel.server import NotificationOptions  # noqa: E402

from apihashing.core.service import ApiHashService  # noqa: E402
from apihashing.core.workspace import init_workspace  # noqa: E402


LOG_LEVEL = os.getenv("APIHASHING_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class ApiBridge:
    def __init__(self, base_url: str, timeout_seconds: float = 60.0) -> None:
        self.client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout_seconds)

    def close(self) -> None:
        self.client.close()

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self.client.get(path, params=params)
        return self._parse_response(response)

    def post_json(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        response = self.client.post(path, json=payload or {})
        return self._parse_response(response)

    def post_files(self, path: str, file_paths: list[Path], field_name: str) -> Any:
        with ExitStack() as stack:
            files: list[tuple[str, tuple[str, Any, str]]] = []
            for file_path in file_paths:
                handle = stack.enter_context(file_path.open("rb"))
                files.append((field_name, (file_path.name, handle, "application/octet-stream")))
            response = self.client.post(path, files=files)
        return self._parse_response(response)

    @staticmethod
    def _parse_response(response: httpx.Response) -> Any:
        try:
            payload = response.json()
        except Exception:
            payload = response.text
        if response.is_error:
            detail = payload.get("detail") if isinstance(payload, dict) else payload
            raise RuntimeError(f"Backend error ({response.status_code}): {detail}")
        return payload


def _compact(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _csv(values: str | None) -> list[str] | None:
    if not values:
        return None
    items = [item.strip() for item in values.split(",") if item.strip()]
    return items or None


def _json_object(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object")
    return payload


def _files(raw_paths: list[str]) -> list[Path]:
    result: list[Path] = []
    for raw in raw_paths:
        path = Path(raw).expanduser().resolve()
        if not path.exists() or not path.is_file():
            raise ValueError(f"File does not exist: {raw}")
        result.append(path)
    if not result:
        raise ValueError("At least one file path is required")
    return result


def build_server(api_base_url: str, timeout_seconds: float, project_root: Path) -> tuple[FastMCP, ApiBridge]:
    bridge = ApiBridge(api_base_url, timeout_seconds=timeout_seconds)
    mcp = FastMCP("apihashing-mcp")

    # Match ghidra bridge behavior: advertise tools/list_changed capability.
    orig_create_init_options = mcp._mcp_server.create_initialization_options

    def _patched_init_options(**kwargs):
        return orig_create_init_options(
            notification_options=NotificationOptions(tools_changed=True),
            **kwargs,
        )

    mcp._mcp_server.create_initialization_options = _patched_init_options

    service_holder: dict[str, ApiHashService] = {}

    def _service() -> ApiHashService:
        service = service_holder.get("service")
        if service is None:
            service = ApiHashService.from_project_root(project_root)
            service_holder["service"] = service
        return service

    @mcp.tool()
    def bridge_ping() -> dict[str, Any]:
        """Minimal MCP liveness probe."""
        return {"ok": True, "server": "apihashing-mcp", "mode": "fastmcp"}

    @mcp.tool()
    def backend_health() -> dict[str, Any]:
        """Query apihashing backend /health endpoint."""
        try:
            health = bridge.get("/health")
            return {"ok": True, "health": health}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp.tool()
    def admin_reload() -> Any:
        return bridge.post_json("/admin/reload", {})

    @mcp.tool()
    def admin_rebuild_native(pack_names: str | None = None, target: str = "all") -> Any:
        return bridge.post_json(
            "/admin/rebuild-native",
            _compact({"pack_names": _csv(pack_names), "target": target}),
        )

    @mcp.tool()
    def packs_list() -> Any:
        return bridge.get("/packs")

    @mcp.tool()
    def packs_set_active(pack_name: str, active: bool) -> Any:
        return bridge.post_json(f"/packs/{pack_name}", {"active": active})

    @mcp.tool()
    def algorithms_list() -> Any:
        return bridge.get("/algorithms")

    @mcp.tool()
    def catalogs_list(
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
        filter_text: str | None = None,
        sort_by: str = "name",
        sort_direction: str = "asc",
    ) -> Any:
        return bridge.get(
            "/catalogs",
            params=_compact(
                {
                    "exclude_hyphenated_dlls": exclude_hyphenated_dlls,
                    "common_windows_dlls_only": common_windows_dlls_only,
                    "filter_text": filter_text,
                    "sort_by": sort_by,
                    "sort_direction": sort_direction,
                }
            ),
        )

    @mcp.tool()
    def hashdb_algorithms() -> Any:
        return bridge.get("/hash")

    @mcp.tool()
    def hashdb_lookup(algorithm_id: str, hash_value: str, xor_value: str | None = None) -> Any:
        return bridge.get(f"/hash/{algorithm_id}/{hash_value}", params=_compact({"xor_value": xor_value}))

    @mcp.tool()
    def hashdb_module_hashes(module_name: str, algorithm_id: str, permutation: str = "") -> Any:
        if permutation:
            return bridge.get(f"/module/{module_name}/{algorithm_id}/{permutation}")
        return bridge.get(f"/module/{module_name}/{algorithm_id}/")

    @mcp.tool()
    def hashdb_hunt(hashes: str, xor_value: str | None = None) -> Any:
        values = _csv(hashes)
        if not values:
            raise ValueError("hashes must contain at least one value")
        return bridge.post_json("/hunt", _compact({"hashes": values, "xor_value": xor_value}))

    @mcp.tool()
    def resolve_hash(
        hash_value: str,
        algorithm_id: str,
        library_names: str | None = None,
        catalog_names: str | None = None,
        xor_value: str | None = None,
        algorithm_params_json: str | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> Any:
        return bridge.post_json(
            "/resolve",
            _compact(
                {
                    "hash_value": hash_value,
                    "algorithm_id": algorithm_id,
                    "library_names": _csv(library_names),
                    "catalog_names": _csv(catalog_names),
                    "xor_value": xor_value,
                    "algorithm_params": _json_object(algorithm_params_json),
                    "exclude_hyphenated_dlls": exclude_hyphenated_dlls,
                    "common_windows_dlls_only": common_windows_dlls_only,
                }
            ),
        )

    @mcp.tool()
    def search_hash(
        hash_value: str,
        algorithm_id: str | None = None,
        library_name: str | None = None,
        library_names: str | None = None,
        catalog_names: str | None = None,
        xor_value: str | None = None,
        algorithm_params_json: str | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> Any:
        return bridge.post_json(
            "/search-hash",
            _compact(
                {
                    "hash_value": hash_value,
                    "algorithm_id": algorithm_id,
                    "library_name": library_name,
                    "library_names": _csv(library_names),
                    "catalog_names": _csv(catalog_names),
                    "xor_value": xor_value,
                    "algorithm_params": _json_object(algorithm_params_json),
                    "exclude_hyphenated_dlls": exclude_hyphenated_dlls,
                    "common_windows_dlls_only": common_windows_dlls_only,
                }
            ),
        )

    @mcp.tool()
    def hash_string(
        algorithm_id: str,
        symbol_name: str,
        library_name: str = "",
        library_names: str | None = None,
        catalog_names: str | None = None,
        xor_value: str | None = None,
        algorithm_params_json: str | None = None,
    ) -> Any:
        return bridge.post_json(
            "/hash-string",
            _compact(
                {
                    "algorithm_id": algorithm_id,
                    "symbol_name": symbol_name,
                    "library_name": library_name,
                    "library_names": _csv(library_names),
                    "catalog_names": _csv(catalog_names),
                    "xor_value": xor_value,
                    "algorithm_params": _json_object(algorithm_params_json),
                }
            ),
        )

    @mcp.tool()
    def export_enum(
        algorithm_id: str,
        library_name: str | None = None,
        library_names: str | None = None,
        catalog_names: str | None = None,
        xor_value: str | None = None,
        algorithm_params_json: str | None = None,
    ) -> Any:
        return bridge.post_json(
            "/export-enum",
            _compact(
                {
                    "algorithm_id": algorithm_id,
                    "library_name": library_name,
                    "library_names": _csv(library_names),
                    "catalog_names": _csv(catalog_names),
                    "xor_value": xor_value,
                    "algorithm_params": _json_object(algorithm_params_json),
                }
            ),
        )

    @mcp.tool()
    def bulk_auto(
        hash_value: str,
        algorithm_id: str,
        library_names: str | None = None,
        catalog_names: str | None = None,
        xor_value: str | None = None,
        algorithm_params_json: str | None = None,
        exclude_hyphenated_dlls: bool = False,
        common_windows_dlls_only: bool = False,
    ) -> Any:
        return bridge.post_json(
            "/bulk-auto",
            _compact(
                {
                    "hash_value": hash_value,
                    "algorithm_id": algorithm_id,
                    "library_names": _csv(library_names),
                    "catalog_names": _csv(catalog_names),
                    "xor_value": xor_value,
                    "algorithm_params": _json_object(algorithm_params_json),
                    "exclude_hyphenated_dlls": exclude_hyphenated_dlls,
                    "common_windows_dlls_only": common_windows_dlls_only,
                }
            ),
        )

    @mcp.tool()
    def analyze_binary_file(file_path: str) -> Any:
        files = _files([file_path])
        return bridge.post_files("/analyze-binary", files, field_name="binary")

    @mcp.tool()
    def build_catalogs_from_files(file_paths: list[str]) -> Any:
        files = _files(file_paths)
        return bridge.post_files("/build-catalogs", files, field_name="binaries")

    @mcp.tool()
    def validate_pack(pack_path: str) -> Any:
        return bridge.post_json("/validate-pack", {"pack_path": pack_path})

    @mcp.tool()
    def scaffold_algorithm(pack_path: str, algorithm_id: str, language: str) -> Any:
        return bridge.post_json(
            "/scaffold/algorithm",
            {
                "pack_path": pack_path,
                "algorithm_id": algorithm_id,
                "language": language,
            },
        )

    @mcp.tool()
    def cli_init_workspace(workspace: str, pack_name: str, no_bundled_packs: bool = False) -> Any:
        result = init_workspace(
            Path(workspace),
            pack_name=pack_name,
            include_bundled_packs=not no_bundled_packs,
        )
        return {
            "workspace_root": str(result.workspace_root),
            "packs_root": str(result.packs_root),
            "created_pack_path": str(result.created_pack_path),
            "copied_bundled_pack_paths": [str(path) for path in result.copied_bundled_pack_paths],
        }

    @mcp.tool()
    def cli_build_catalog(input_paths: list[str]) -> Any:
        service = _service()
        result = service.build_catalogs_from_paths([Path(item) for item in input_paths])
        return result.model_dump(mode="json", exclude_none=True)

    return mcp, bridge


def main() -> int:
    parser = argparse.ArgumentParser(description="apihashing MCP bridge")
    parser.add_argument(
        "--mcp-host",
        type=str,
        default="127.0.0.1",
        help="Host for HTTP transport (streamable-http or sse).",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=None,
        help="Port for HTTP transport (streamable-http or sse).",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="MCP transport.",
    )
    parser.add_argument(
        "--lazy",
        action="store_true",
        default=False,
        help="Compatibility flag with ghidra bridge (currently no-op).",
    )
    parser.add_argument(
        "--no-lazy",
        dest="lazy",
        action="store_false",
        help="Compatibility flag with ghidra bridge (currently no-op).",
    )
    args = parser.parse_args()

    api_base_url = os.environ.get("APIHASHING_MCP_API_URL", "http://127.0.0.1:8000")
    timeout_seconds = float(os.environ.get("APIHASHING_MCP_TIMEOUT_SECONDS", "60"))
    project_root = Path(os.environ.get("APIHASHING_PROJECT_ROOT", str(Path.cwd()))).resolve()

    mcp, bridge = build_server(
        api_base_url=api_base_url,
        timeout_seconds=timeout_seconds,
        project_root=project_root,
    )

    mcp.settings.log_level = "INFO"
    mcp.settings.host = args.mcp_host
    if args.mcp_port:
        mcp.settings.port = args.mcp_port

    logger.info("Starting apihashing MCP bridge (%s)", args.transport)
    try:
        mcp.run(transport=args.transport)
    finally:
        bridge.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
