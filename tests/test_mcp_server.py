from __future__ import annotations

from pathlib import Path

from apihashing.mcp_server import build_server


def test_build_server_registers_rest_and_cli_scope_tools(tmp_path: Path) -> None:
    server, bridge = build_server("http://127.0.0.1:8000", 1.0, tmp_path)
    try:
        tools = set(server._tool_manager._tools.keys())
        expected_subset = {
            "bridge_ping",
            "backend_health",
            "admin_reload",
            "admin_rebuild_native",
            "packs_list",
            "packs_set_active",
            "algorithms_list",
            "catalogs_list",
            "hashdb_algorithms",
            "hashdb_lookup",
            "hashdb_module_hashes",
            "hashdb_hunt",
            "resolve_hash",
            "search_hash",
            "hash_string",
            "export_enum",
            "bulk_auto",
            "analyze_binary_file",
            "build_catalogs_from_files",
            "validate_pack",
            "scaffold_algorithm",
            "cli_init_workspace",
            "cli_build_catalog",
        }
        assert expected_subset.issubset(tools)
    finally:
        bridge.close()
