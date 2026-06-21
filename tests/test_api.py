import asyncio
from pathlib import Path
import shutil
import subprocess
import zlib

import httpx

from apihashing.app import create_app
from apihashing.core.analyzer import _entry_name
from apihashing.core.models import CatalogRecord
from apihashing.core.service import ApiHashService


async def _request(app, method: str, url: str, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.request(method, url, **kwargs)


def _payouts_king_crc32(input_string: bytes) -> int:
    checksum = 0
    poly = 0xBDC65592
    for char_val in input_string:
        char_val |= 0x20
        checksum ^= char_val
        for _ in range(8):
            if checksum & 1:
                checksum = (checksum >> 1) ^ poly
            else:
                checksum >>= 1
            checksum &= 0xFFFFFFFF
    return checksum


def _write_multibase_test_pack(root: Path) -> None:
    pack_dir = root / "packs" / "param-pack"
    (pack_dir / "catalogs").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "symbols.json").write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "param_crc.py").write_text(
        """
import zlib
from apihashing.plugin_api import FunctionHashImplementation

def _hash(library_name, symbol_name, params):
    base = int(params.get("base", 0))
    return (zlib.crc32(f"{library_name}{symbol_name}".encode("utf-8")) + base) & 0xFFFFFFFF

HASH_IMPLEMENTATION = FunctionHashImplementation(id="param_crc32", callback=_hash, hash_size_bits=32)
""".lstrip(),
        encoding="utf-8",
    )


def test_api_lists_algorithms() -> None:
    project_root = Path(__file__).resolve().parents[1]
    native_dir = project_root / "packs" / "default-pack" / "algorithms" / "native"
    if shutil.which("make") is None or shutil.which("gcc") is None:
        raise AssertionError("make and gcc are required for this test")
    subprocess.run(["make", "-C", str(native_dir), "all"], check=True)

    app = create_app(project_root)

    response = asyncio.run(_request(app, "GET", "/algorithms"))

    assert response.status_code == 200
    payload = response.json()
    algorithm_ids = {item["id"] for item in payload}
    assert "payouts_king_crc32" in algorithm_ids
    assert "internal_djb2_symbol_c" in algorithm_ids
    payouts = next(item for item in payload if item["id"] == "payouts_king_crc32")
    assert payouts["implementation_type"] == "python"
    assert payouts["hash_size_bits"] == 32
    assert payouts["author"] == "Zscaler ThreatLabz"
    assert payouts["copied_from_flare_shellcode"] is False
    assert payouts["source"] == "https://www.zscaler.com/blogs/security-research/payouts-king-takes-aim-ransomware-throne"
    ror13 = next(item for item in payload if item["id"] == "ror13_add")
    assert ror13["author"] == "OALabs/hashdb contributors"
    assert ror13["copied_from_flare_shellcode"] is True
    native = next(item for item in payload if item["id"] == "internal_djb2_symbol_c")
    assert native["implementation_type"] == "c_shared"
    assert native["pack"] == "default-pack"
    assert native["author"] == "Internal Research Team"


def test_api_resolves_hashes_from_catalogs() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    target = _payouts_king_crc32(b"CreateFileW")

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/resolve",
            json={"hash_value": target, "algorithm_id": "payouts_king_crc32"},
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert any(
        item["library"] == "kernel32.dll"
        and item["symbol"] == "CreateFileW"
        and item["hash_value_hex"] == f"{target:08x}"
        for item in payload["matches"]
    )


def test_api_resolve_accepts_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)
    target = ((zlib.crc32(b"demo.dllDemoExport") & 0xFFFFFFFF) + 0x20) & 0xFFFFFFFF

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/resolve",
            json={
                "hash_value": target,
                "algorithm_id": "param_crc32",
                "algorithm_params": {"base_values": ["0x10", "0x20"]},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert len(payload["matches"]) == 1
    assert payload["matches"][0]["library"] == "demo.dll"
    assert payload["matches"][0]["symbol"] == "DemoExport"
    assert payload["matches"][0]["base_value"] == 32


def test_api_resolve_applies_xor_value_without_rewriting_query_input(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)
    base_value = zlib.crc32(b"demo.dllDemoExport") & 0xFFFFFFFF
    xor_value = 0x13579BDF
    obfuscated = base_value ^ xor_value

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/resolve",
            json={
                "hash_value": obfuscated,
                "algorithm_id": "param_crc32",
                "xor_value": xor_value,
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["query_hash_input"] == str(obfuscated)
    assert payload["query_hash_unsigned_int"] == base_value
    assert len(payload["matches"]) == 1
    assert payload["matches"][0]["library"] == "demo.dll"
    assert payload["matches"][0]["symbol"] == "DemoExport"


def test_api_analyzes_local_binary_with_lief() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    python_binary = Path("/usr/bin/python3")

    with python_binary.open("rb") as handle:
        response = asyncio.run(
            _request(
                app,
                "POST",
                "/analyze-binary",
                files={"binary": ("python3", handle, "application/octet-stream")},
            )
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["binary_family"] in {"elf", "pe", "macho"}
    assert isinstance(payload["imports"], list)


def test_api_lists_packs_and_catalogs() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    packs_response = asyncio.run(_request(app, "GET", "/packs"))
    catalogs_response = asyncio.run(_request(app, "GET", "/catalogs"))

    assert packs_response.status_code == 200
    assert catalogs_response.status_code == 200
    assert packs_response.json()[0]["name"] == "default-pack"
    catalogs = catalogs_response.json()
    assert any(item["library"] == "kernel32.dll" and "kind" not in item for item in catalogs)
    assert any(item["library"] == "payouts_king_wordlist" and item["kind"] == "wordlist" for item in catalogs)


def test_api_filters_catalogs_to_common_windows_dlls_and_excludes_hyphenated_names() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "GET",
            "/catalogs?exclude_hyphenated_dlls=true&common_windows_dlls_only=true",
        )
    )

    assert response.status_code == 200
    catalogs = response.json()
    assert any(item["library"] == "kernel32.dll" for item in catalogs)
    assert not any(item.get("kind") != "wordlist" and "-" in item["library"] for item in catalogs)
    assert not any(item.get("kind") != "wordlist" and item["library"] == "AppXDeploymentExtensions.onecore.dll" for item in catalogs)


def test_api_searches_hash_across_all_algorithms() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={"hash_value": "0x7c0017bb"},
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["execution_mode"] in {"single_thread", "threadpool", "process_pool"}
    assert payload["worker_count"] >= 1
    assert payload["algorithm_count"] >= 1
    assert any(item["algorithm_id"] == "ror13_add" for item in payload["results"])


def test_api_search_hash_accepts_library_scope_flags() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    target = _payouts_king_crc32(b"CreateFileW")

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={
                "hash_value": target,
                "exclude_hyphenated_dlls": True,
                "common_windows_dlls_only": True,
                "catalogs": [
                    {"library": "kernel32.dll", "symbols": ["CreateFileW"]},
                    {"library": "api-ms-win-core-file-l1-2-0.dll", "symbols": ["CreateFileW"]},
                ],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert any(item["library"] == "kernel32.dll" for item in payload["results"])
    assert not any("-" in item["library"] for item in payload["results"])


def test_api_search_hash_accepts_optional_algorithm_filter() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={
                "hash_value": "0x7c0017bb",
                "algorithm_id": "ror13_add",
                "library_name": "kernel32",
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_count"] == 1
    assert payload["results"]
    assert {item["algorithm_id"] for item in payload["results"]} == {"ror13_add"}


def test_api_search_hash_rejects_conflicting_library_name_and_library_names() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={
                "hash_value": "0x7c0017bb",
                "library_name": "kernel32.dll",
                "library_names": ["kernel32.dll"],
            },
        )
    )

    assert response.status_code == 422


def test_api_search_hash_transient_catalog_overrides_same_named_active_catalog() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    target = _payouts_king_crc32(b"CreateFileW")

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={
                "hash_value": target,
                "library_name": "kernel32.dll",
                "catalogs": [{"library": "kernel32.dll", "symbols": ["TransientOnly"]}],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["results"] == []


def test_api_supports_hashdb_lookup_routes() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    target = 2080380859

    algorithms = asyncio.run(_request(app, "GET", "/hash"))
    lookup = asyncio.run(_request(app, "GET", f"/hash/ror13_add/{target}"))
    module = asyncio.run(_request(app, "GET", "/module/kernel32.dll/ror13_add/"))
    hunt = asyncio.run(_request(app, "POST", "/hunt", json={"hashes": [target]}))

    assert algorithms.status_code == 200
    assert lookup.status_code == 200
    assert module.status_code == 200
    assert hunt.status_code == 200
    assert any(item["algorithm"] == "ror13_add" for item in algorithms.json()["algorithms"])
    assert lookup.json()["hashes"][0]["string"]["api"] == "CreateFileW"
    assert module.json()["hashes"][0]["string"]["module"] == "kernel32.dll"
    assert any(item["algorithm"] == "ror13_add" for item in hunt.json()["hits"])


def test_api_supports_xor_modifier_on_hash_routes() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    base = _payouts_king_crc32(b"CreateFileW")
    xor_value = 0x13579BDF
    obfuscated = base ^ xor_value

    search = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={"hash_value": obfuscated, "xor_value": xor_value},
        )
    )
    hashed = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "payouts_king_crc32",
                "symbol_name": "CreateFileW",
                "library_name": "kernel32.dll",
                "xor_value": xor_value,
            },
        )
    )

    assert search.status_code == 200
    assert hashed.status_code == 200
    assert any(item["algorithm_id"] == "payouts_king_crc32" for item in search.json()["results"])
    assert hashed.json()["hash_value_unsigned_int"] == obfuscated


def test_api_supports_hashdb_ida_client_sequence_with_xor() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    base = 2080380859
    xor_value = 0x13579BDF
    obfuscated = base ^ xor_value

    algorithms = asyncio.run(_request(app, "GET", "/hash"))
    lookup = asyncio.run(_request(app, "GET", f"/hash/ror13_add/{obfuscated}?xor_value={xor_value}"))
    module_plain = asyncio.run(_request(app, "GET", "/module/kernel32.dll/ror13_add/"))
    module = asyncio.run(_request(app, "GET", f"/module/kernel32.dll/ror13_add/?xor_value={xor_value}"))
    hunt = asyncio.run(_request(app, "POST", "/hunt", json={"hashes": [obfuscated], "xor_value": xor_value}))

    assert algorithms.status_code == 200
    assert lookup.status_code == 200
    assert module_plain.status_code == 200
    assert module.status_code == 200
    assert hunt.status_code == 200
    assert any(item["algorithm"] == "ror13_add" for item in algorithms.json()["algorithms"])
    assert any(item["string"]["api"] == "CreateFileW" for item in lookup.json()["hashes"])
    assert any(item["string"]["api"] == "CreateFileW" for item in module.json()["hashes"])
    assert module.json() == module_plain.json()
    assert any(item["algorithm"] == "ror13_add" for item in hunt.json()["hits"])


def test_api_hashes_string_for_requested_algorithm() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "payouts_king_crc32",
                "symbol_name": "GetProcAddress",
                "library_name": "kernel32.dll",
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["hash_value_hex"] == f"{_payouts_king_crc32(b'GetProcAddress'):08x}"


def test_api_hash_string_accepts_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_name": "demo.dll",
                "algorithm_params": {"base_values": ["0x10", "0x20"]},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert payload["library_name"] == "demo.dll"
    assert payload["symbol_name"] == "DemoExport"
    assert [item["base_value"] for item in payload["results"]] == [16, 32]
    assert {item["hash_value_unsigned_int"] for item in payload["results"]} == {
        ((zlib.crc32(b"demo.dllDemoExport") & 0xFFFFFFFF) + 0x10) & 0xFFFFFFFF,
        ((zlib.crc32(b"demo.dllDemoExport") & 0xFFFFFFFF) + 0x20) & 0xFFFFFFFF,
    }


def test_api_hash_string_with_library_and_single_base_keeps_legacy_single_result_shape(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_name": "demo.dll",
                "algorithm_params": {"base": "0x10"},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert payload["library_name"] == "demo.dll"
    assert payload["symbol_name"] == "DemoExport"
    assert payload["base_value"] == 16
    assert payload["hash_value_hex"] == f"{((zlib.crc32(b'demo.dllDemoExport') & 0xFFFFFFFF) + 0x10) & 0xFFFFFFFF:08x}"
    assert "results" not in payload


def test_api_hash_string_with_multiple_libraries_and_base_values_returns_batch_shape(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    pack_dir = tmp_path / "packs" / "param-pack"
    (pack_dir / "catalogs" / "symbols-two.json").write_text(
        '{"library":"demo-two.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_names": ["demo.dll", "demo-two.dll"],
                "algorithm_params": {"base_values": ["0x10", "0x20"]},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert payload["libraries"] == ["demo.dll", "demo-two.dll"]
    assert payload["symbol_name"] == "DemoExport"
    assert "library_name" not in payload
    assert len(payload["results"]) == 4
    assert {(item["library_name"], item["base_value"]) for item in payload["results"]} == {
        ("demo.dll", 16),
        ("demo.dll", 32),
        ("demo-two.dll", 16),
        ("demo-two.dll", 32),
    }


def test_api_hash_string_rejects_conflicting_library_name_and_library_names(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_name": "demo.dll",
                "library_names": ["demo.dll"],
            },
        )
    )

    assert response.status_code == 422


def test_api_hash_string_rejects_mixed_base_and_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_name": "demo.dll",
                "algorithm_params": {"base": "0x10", "base_values": ["0x20"]},
            },
        )
    )

    assert response.status_code == 400


def test_api_hash_string_allows_library_names_with_catalog_names_via_intersection(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    pack_dir = tmp_path / "packs" / "param-pack"
    (pack_dir / "catalogs" / "symbols-two.json").write_text(
        '{"library":"demo-two.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_names": ["demo-two.dll"],
                "catalog_names": ["demo.dll", "demo-two.dll"],
                "algorithm_params": {"base_values": ["0x10", "0x20"]},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["libraries"] == ["demo-two.dll"]
    assert len(payload["results"]) == 2
    assert {(item["library_name"], item["base_value"]) for item in payload["results"]} == {
        ("demo-two.dll", 16),
        ("demo-two.dll", 32),
    }


def test_api_hash_string_uses_catalog_names_for_catalog_selection(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    pack_dir = tmp_path / "packs" / "param-pack"
    (pack_dir / "catalogs" / "wordlist.json").write_text(
        '{"kind":"wordlist","library":"demo-words","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "catalog_names": ["demo-words"],
                "algorithm_params": {"base_values": ["0x10", "0x20"]},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["libraries"] == ["demo-words"]
    assert len(payload["results"]) == 2
    assert {(item["library_name"], item["base_value"]) for item in payload["results"]} == {
        ("", 16),
        ("", 32),
    }


def test_api_hash_string_without_library_keeps_legacy_single_result_shape(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "algorithm_params": {"base": "0x10"},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert payload["library_name"] == ""
    assert payload["symbol_name"] == "DemoExport"
    assert payload["base_value"] == 16
    assert "results" not in payload
    assert payload["hash_value_unsigned_int"] == ((zlib.crc32(b"DemoExport") & 0xFFFFFFFF) + 0x10) & 0xFFFFFFFF


def test_api_bulk_auto_uses_transient_catalogs_for_matching(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)
    target = zlib.crc32(b"transient.dllDemoExport") & 0xFFFFFFFF

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/bulk-auto",
            json={
                "hash_value": target,
                "algorithm_id": "param_crc32",
                "catalog_names": ["transient.dll"],
                "catalogs": [{"library": "transient.dll", "symbols": ["DemoExport"]}],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["matches"]) == 1
    assert payload["matches"][0]["library"] == "transient.dll"
    assert payload["matches"][0]["symbol"] == "DemoExport"
    assert len(payload["exports"]) == 1
    assert payload["exports"][0]["library"] == "transient.dll"


def test_api_openapi_includes_multi_base_examples() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(_request(app, "GET", "/openapi.json"))

    assert response.status_code == 200
    payload = response.json()
    resolve_request = payload["components"]["schemas"]["ResolveRequest"]
    search_hash_request = payload["components"]["schemas"]["SearchHashRequest"]
    hash_string_request = payload["components"]["schemas"]["HashStringRequest"]
    export_enum_request = payload["components"]["schemas"]["ExportEnumRequest"]
    bulk_auto_request = payload["components"]["schemas"]["BulkAutoRequest"]
    assert resolve_request["examples"][0]["algorithm_params"]["base_values"] == ["0x10", "0x20"]
    assert search_hash_request["examples"][0]["algorithm_params"]["base_values"] == ["0x10", "0x20"]
    assert hash_string_request["examples"][0]["algorithm_params"]["base_values"] == ["0x10", "0x20"]
    assert export_enum_request["examples"][0]["algorithm_params"]["base_values"] == ["0x10", "0x20"]
    assert bulk_auto_request["examples"][0]["algorithm_params"]["base_values"] == ["0x10", "0x20"]


def test_api_hashes_string_with_algorithm_params(tmp_path: Path) -> None:
    pack_dir = tmp_path / "packs" / "param-pack"
    (pack_dir / "catalogs").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "symbols.json").write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "param_crc.py").write_text(
        """
import zlib
from apihashing.plugin_api import FunctionHashImplementation

def _hash(library_name, symbol_name, params):
    base = int(params.get("base", 0))
    return (zlib.crc32(f"{library_name}{symbol_name}".encode("utf-8")) + base) & 0xFFFFFFFF

HASH_IMPLEMENTATION = FunctionHashImplementation(id="param_crc32", callback=_hash, hash_size_bits=32)
""".lstrip(),
        encoding="utf-8",
    )
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_name": "demo.dll",
                "algorithm_params": {"base": "0x1000"},
            },
        )
    )

    assert response.status_code == 200
    assert response.json()["hash_value_unsigned_int"] == ((zlib.crc32(b"demo.dllDemoExport") & 0xFFFFFFFF) + 0x1000) & 0xFFFFFFFF


def test_api_builds_merged_catalog_from_uploaded_binaries() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    shared_library = Path("/lib64/libc.so.6")

    with shared_library.open("rb") as handle_a, shared_library.open("rb") as handle_b:
        response = asyncio.run(
            _request(
                app,
                "POST",
                "/build-catalogs",
                files=[
                    ("binaries", ("libc.so.6", handle_a, "application/octet-stream")),
                    ("binaries", ("libc-copy.so.6", handle_b, "application/octet-stream")),
                ],
            )
        )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["libraries"]) == 2
    assert payload["libraries"][0]["library"] == "libc.so.6"
    assert payload["libraries"][0]["symbols"]
    assert "kind" not in payload["libraries"][0]


def test_service_builds_catalogs_from_filesystem_paths(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)
    shared_library = Path("/lib64/libc.so.6")
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    sample_path = sample_dir / "libc.so.6"
    sample_path.write_bytes(shared_library.read_bytes())

    merged = service.build_catalogs_from_paths([sample_dir])

    assert any(entry.library == "libc.so.6" for entry in merged.libraries)


def test_service_renders_c_header_enum_for_library() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    rendered = service.export_enum_for_library("payouts_king_crc32", "kernel32.dll")

    assert rendered.library == "kernel32.dll"
    assert rendered.algorithm_id == "payouts_king_crc32"
    assert "typedef enum {" in rendered.header_text
    expected = _payouts_king_crc32(b"CreateFileW")
    assert f"apihashing_payouts_king_crc32_kernel32_dll_CreateFileW = 0x{expected:X}" in rendered.header_text


def test_analyzer_extracts_clean_export_name_from_lief_style_string() -> None:
    class FakeEntry:
        def __str__(self) -> str:
            return "0x0000000000: CreateFileW (0x0000 bytes)"

    assert _entry_name(FakeEntry()) == "CreateFileW"


def test_api_searches_hash_with_transient_wordlists() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    target = _payouts_king_crc32(b"-backup")

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={
                "hash_value": target,
                "catalogs": [
                    {
                        "name": "command_line_args",
                        "symbols": ["-backup"],
                    }
                ],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert any(item["catalog_kind"] == "wordlist" and item["symbol"] == "-backup" for item in payload["results"])


def test_api_exports_enum_from_transient_catalogs() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/export-enum",
            json={
                "algorithm_id": "payouts_king_crc32",
                "library_name": "transient.dll",
                "catalogs": [
                    {
                        "library": "transient.dll",
                        "symbols": ["CreateFileW"],
                    }
                ],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["library"] == "transient.dll"
    assert "apihashing_payouts_king_crc32_transient_dll_CreateFileW" in payload["header_text"]


def test_api_export_enum_transient_catalog_overrides_same_named_active_catalog() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/export-enum",
            json={
                "algorithm_id": "payouts_king_crc32",
                "library_name": "kernel32.dll",
                "catalogs": [{"library": "kernel32.dll", "symbols": ["TransientOnly"]}],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert "TransientOnly" in payload["header_text"]
    assert "CreateFileW" not in payload["header_text"]


def test_service_renders_c_header_enum_with_sanitized_unique_identifiers() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    rendered = service.export_enum_for_library(
        "payouts_king_crc32",
        "api-ms-win-core-file-l1-2-0.dll",
        catalogs=[
            CatalogRecord(
                binary_family="pe",
                library="api-ms-win-core-file-l1-2-0.dll",
                symbols=["Create-FileW", "A B", "A-B", "switch", "123name", "?Func@@YAXH@Z"],
            )
        ],
    )

    assert rendered.enum_name == "apihashing_payouts_king_crc32_api_ms_win_core_file_l1_2_0_dll"
    assert "apihashing_payouts_king_crc32_api_ms_win_core_file_l1_2_0_dll_Create_FileW" in rendered.header_text
    assert "apihashing_payouts_king_crc32_api_ms_win_core_file_l1_2_0_dll_A_B =" in rendered.header_text
    assert "apihashing_payouts_king_crc32_api_ms_win_core_file_l1_2_0_dll_A_B_" in rendered.header_text
    assert "apihashing_payouts_king_crc32_api_ms_win_core_file_l1_2_0_dll_switch =" in rendered.header_text
    assert "apihashing_payouts_king_crc32_api_ms_win_core_file_l1_2_0_dll_123name =" in rendered.header_text
    assert "?Func" not in rendered.header_text


def test_service_parses_ida_and_prefixed_hex_values() -> None:
    assert ApiHashService._parse_hash_value("7C0017BBh") == 0x7C0017BB
    assert ApiHashService._parse_hash_value("0x7C0017BB") == 0x7C0017BB
    assert ApiHashService._parse_hash_value("2080380859") == 2080380859


def test_api_accepts_ida_style_hex_search_value() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/search-hash",
            json={"hash_value": "7C0017BBh"},
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["query_hash_unsigned_int"] == 0x7C0017BB
    assert any(item["algorithm_id"] == "ror13_add" for item in payload["results"])


def test_api_catalogs_support_backend_filtering_and_sorting() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "GET",
            "/catalogs?filter_text=kernel&sort_by=export_count&sort_direction=desc&common_windows_dlls_only=true",
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload
    assert all("kernel" in item["library"].lower() for item in payload)
    assert payload == sorted(payload, key=lambda item: item["export_count"], reverse=True)


def test_api_resolve_accepts_library_and_catalog_scope_lists() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    target = _payouts_king_crc32(b"CreateFileW")

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/resolve",
            json={
                "hash_value": target,
                "algorithm_id": "payouts_king_crc32",
                "library_names": ["kernel32.dll"],
                "catalog_names": ["kernel32.dll"],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["matches"]
    assert {item["library"] for item in payload["matches"]} == {"kernel32.dll"}


def test_api_hash_string_accepts_multiple_libraries() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "payouts_king_crc32",
                "symbol_name": "GetProcAddress",
                "library_names": ["kernel32.dll", "user32.dll"],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["libraries"] == ["kernel32.dll", "user32.dll"]
    assert len(payload["results"]) == 1
    assert payload["results"][0]["library_name"] == ""


def test_api_hash_string_keeps_multiple_results_for_library_sensitive_algorithms(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/hash-string",
            json={
                "algorithm_id": "param_crc32",
                "symbol_name": "DemoExport",
                "library_names": ["demo.dll", "demo2.dll"],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["libraries"] == ["demo.dll", "demo2.dll"]
    assert len(payload["results"]) == 2
    assert {item["library_name"] for item in payload["results"]} == {"demo.dll", "demo2.dll"}


def test_api_export_enum_accepts_multiple_libraries_and_catalog_selection(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/export-enum",
            json={
                "algorithm_id": "param_crc32",
                "library_names": ["demo.dll"],
                "catalog_names": ["demo.dll"],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert payload["libraries"] == ["demo.dll"]
    assert payload["exports"][0]["library"] == "demo.dll"


def test_api_export_enum_multiple_libraries_preserves_input_order_with_parallel_workers(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    extra_catalog = (
        tmp_path
        / "packs"
        / "param-pack"
        / "catalogs"
        / "symbols_2.json"
    )
    extra_catalog.write_text(
        '{"library":"demo2.dll","symbols":["DemoExport2"]}',
        encoding="utf-8",
    )
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/export-enum",
            json={
                "algorithm_id": "param_crc32",
                "library_names": ["demo2.dll", "demo.dll"],
                "catalog_names": ["demo.dll", "demo2.dll"],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["libraries"] == ["demo2.dll", "demo.dll"]
    assert [item["library"] for item in payload["exports"]] == ["demo2.dll", "demo.dll"]


def test_api_export_enum_with_library_and_multiple_base_values_returns_aggregate_shape(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/export-enum",
            json={
                "algorithm_id": "param_crc32",
                "library_name": "demo.dll",
                "algorithm_params": {"base_values": ["0x10", "0x20"]},
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert payload["library_name"] == "demo.dll"
    assert [item["base_value"] for item in payload["results"]] == [16, 32]
    assert "exports" not in payload


def test_api_export_enum_rejects_conflicting_library_name_and_library_names() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/export-enum",
            json={
                "algorithm_id": "payouts_king_crc32",
                "library_name": "kernel32.dll",
                "library_names": ["kernel32.dll"],
            },
        )
    )

    assert response.status_code == 422


def test_api_pack_toggles_update_process_local_active_state() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    initial = asyncio.run(_request(app, "GET", "/packs"))
    updated = asyncio.run(
        _request(
            app,
            "POST",
            "/packs/default-pack",
            json={"active": False},
        )
    )
    after = asyncio.run(_request(app, "GET", "/packs"))

    assert initial.status_code == 200
    assert updated.status_code == 200
    assert after.status_code == 200
    assert any(item["name"] == "default-pack" and item["active"] is False for item in after.json())


def test_api_pack_toggle_removes_algorithms_from_inactive_pack() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    before = asyncio.run(_request(app, "GET", "/algorithms"))
    toggled = asyncio.run(
        _request(
            app,
            "POST",
            "/packs/oalabs-hashdb",
            json={"active": False},
        )
    )
    after = asyncio.run(_request(app, "GET", "/algorithms"))

    assert before.status_code == 200
    assert toggled.status_code == 200
    assert after.status_code == 200
    assert any(item["id"] == "ror13_add" for item in before.json())
    assert not any(item["id"] == "ror13_add" for item in after.json())


def test_api_bulk_auto_returns_matches_and_rendered_enums(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    app = create_app(tmp_path)
    target = zlib.crc32(b"demo.dllDemoExport") & 0xFFFFFFFF

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/bulk-auto",
            json={
                "hash_value": target,
                "algorithm_id": "param_crc32",
                "library_names": ["demo.dll"],
                "catalog_names": ["demo.dll"],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_id"] == "param_crc32"
    assert any(item["library"] == "demo.dll" for item in payload["matches"])
    assert payload["exports"][0]["library"] == "demo.dll"


def test_api_bulk_auto_transient_catalog_overrides_same_named_active_catalog() -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    target = _payouts_king_crc32(b"CreateFileW")

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/bulk-auto",
            json={
                "hash_value": target,
                "algorithm_id": "payouts_king_crc32",
                "library_names": ["kernel32.dll"],
                "catalog_names": ["kernel32.dll"],
                "catalogs": [{"library": "kernel32.dll", "symbols": ["TransientOnly"]}],
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["matches"] == []
    assert payload["exports"] == []


def test_api_admin_reload_picks_up_new_pack_without_restart(tmp_path: Path) -> None:
    packs_root = tmp_path / "packs"
    base_pack = packs_root / "base-pack"
    (base_pack / "catalogs").mkdir(parents=True)
    (base_pack / "catalogs" / "base.json").write_text('{"library":"base.dll","symbols":["BaseExport"]}', encoding="utf-8")
    app = create_app(tmp_path)

    before = asyncio.run(_request(app, "GET", "/packs"))
    assert before.status_code == 200
    assert [item["name"] for item in before.json()] == ["base-pack"]

    hot_pack = packs_root / "hot-pack"
    (hot_pack / "catalogs").mkdir(parents=True)
    (hot_pack / "algorithms").mkdir(parents=True)
    (hot_pack / "catalogs" / "hot.json").write_text('{"library":"hot.dll","symbols":["HotExport"]}', encoding="utf-8")
    (hot_pack / "algorithms" / "hot.hash.py").write_text(
        (
            "from apihashing.plugin_api import FunctionHashImplementation\n\n"
            "def _hash(library_name, symbol_name):\n"
            "    return 0x11223344\n\n"
            "HASH_IMPLEMENTATION = FunctionHashImplementation(\n"
            "    id='hot_hash',\n"
            "    callback=_hash,\n"
            "    hash_size_bits=32,\n"
            ")\n"
        ),
        encoding="utf-8",
    )

    reloaded = asyncio.run(_request(app, "POST", "/admin/reload", json={}))
    assert reloaded.status_code == 200
    assert reloaded.json()["reloaded"] is True

    after = asyncio.run(_request(app, "GET", "/packs"))
    algorithms = asyncio.run(_request(app, "GET", "/algorithms"))
    assert after.status_code == 200
    assert algorithms.status_code == 200
    assert any(item["name"] == "hot-pack" for item in after.json())
    assert any(item["id"] == "hot_hash" for item in algorithms.json())


def test_api_admin_rebuild_native_runs_make_then_reloads() -> None:
    if shutil.which("make") is None or shutil.which("gcc") is None:
        raise AssertionError("make and gcc are required for this test")
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/admin/rebuild-native",
            json={"pack_names": ["default-pack"], "target": "all"},
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["rebuilt"] is True
    assert payload["reload"]["reloaded"] is True
