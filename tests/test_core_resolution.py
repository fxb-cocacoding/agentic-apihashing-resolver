from pathlib import Path
import shutil
import subprocess
import threading
import textwrap
import time
from unittest.mock import patch
import zlib

import pytest

from apihashing.app import create_app
from apihashing.core.models import AlgorithmMetadata, CatalogRecord, ExportedHeaderAggregateResult, ExportedHeaderResult, HashStringAggregateResult, HashStringResult
from apihashing.core.service import ApiHashService


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


def _internal_djb2_lower(input_string: bytes) -> int:
    value = 5381
    for item in input_string:
        if 0x41 <= item <= 0x5A:
            item |= 0x20
        value = ((value << 5) + value + item) & 0xFFFFFFFF
    return value


def _write_multibase_test_pack(tmp_path: Path) -> None:
    pack_dir = tmp_path / "packs" / "multibase-pack"
    (pack_dir / "catalogs").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "kernel32.json").write_text(
        '{"library":"kernel32.dll","symbols":["CreateFileW","GetProcAddress"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "payouts_king_crc32.hash.py").write_text(
        textwrap.dedent(
            """
            from apihashing.plugin_api import FunctionHashImplementation


            def payouts_king_crc32(input_string: bytes) -> int:
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


            def _hash(library_name: str, symbol_name: str, params: dict[str, object]) -> int:
                del library_name
                base = int(params.get("base", 0))
                return (payouts_king_crc32(symbol_name.encode('utf-8')) + base) & 0xFFFFFFFF


            HASH_IMPLEMENTATION = FunctionHashImplementation(
                id='payouts_king_crc32',
                display_name='Payouts King CRC32',
                callback=_hash,
                hash_size_bits=32,
            )
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )


def test_service_resolves_payouts_king_crc32_for_default_pack() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)
    target = _payouts_king_crc32(b"CreateFileW")

    result = service.resolve_hash(target, algorithm_id="payouts_king_crc32")

    assert result.algorithm_id == "payouts_king_crc32"
    assert result.query_hash_unsigned_int == target
    assert any(
        match.library == "kernel32.dll"
        and match.symbol == "CreateFileW"
        and match.pack == "default-pack"
        and match.hash_size_bits == 32
        for match in result.matches
    )


def test_service_loads_default_native_c_algorithm_and_hashes_symbols() -> None:
    project_root = Path(__file__).resolve().parents[1]
    native_dir = project_root / "packs" / "default-pack" / "algorithms" / "native"
    if shutil.which("make") is None or shutil.which("gcc") is None:
        pytest.skip("make and gcc are required for default native C algorithm test")
    subprocess.run(["make", "-C", str(native_dir), "all"], check=True)

    service = ApiHashService.from_project_root(project_root)
    metadata = next(item for item in service.list_algorithms() if item.id == "internal_djb2_symbol_c")

    hashed = service.hash_string_for_algorithm(
        algorithm_id="internal_djb2_symbol_c",
        symbol_name="GetProcAddress",
        library_name="kernel32.dll",
    )

    assert metadata.implementation_type == "c_shared"
    assert metadata.pack == "default-pack"
    assert metadata.author == "Internal Research Team"
    assert hashed.hash_value_unsigned_int == _internal_djb2_lower(b"GetProcAddress")


def test_service_resolve_hash_tries_multiple_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    service = ApiHashService.from_project_root(tmp_path)
    target = (_payouts_king_crc32(b"CreateFileW") + 0x10) & 0xFFFFFFFF

    result = service.resolve_hash(
        target,
        algorithm_id="payouts_king_crc32",
        algorithm_params={"base_values": ["0x10", "0x20"]},
    )

    assert len(result.matches) == 1
    assert result.matches[0].base_value == 16


def test_service_preserves_non_base_hex_like_algorithm_params_as_strings(tmp_path: Path) -> None:
    pack_dir = tmp_path / "packs" / "param-pack"
    (pack_dir / "catalogs").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "symbols.json").write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "param_type.hash.py").write_text(
        textwrap.dedent(
            """
            from apihashing.plugin_api import FunctionHashImplementation


            def _hash(library_name: str, symbol_name: str, params: dict[str, object]) -> int:
                del library_name, symbol_name
                marker = params.get("marker")
                if isinstance(marker, str):
                    return 1
                if isinstance(marker, int):
                    return 2
                return 0


            HASH_IMPLEMENTATION = FunctionHashImplementation(
                id='param_type',
                callback=_hash,
                hash_size_bits=32,
            )
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    service = ApiHashService.from_project_root(tmp_path)

    result = service.hash_string_for_algorithm(
        algorithm_id="param_type",
        symbol_name="DemoExport",
        library_name="demo.dll",
        algorithm_params={"marker": "0x10"},
    )

    assert result.hash_value_unsigned_int == 1


def test_service_hash_string_emits_one_result_per_library_and_base_value(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    service = ApiHashService.from_project_root(tmp_path)

    result = service.hash_string_for_libraries(
        algorithm_id="payouts_king_crc32",
        symbol_name="GetProcAddress",
        library_names=["kernel32.dll"],
        algorithm_params={"base_values": ["0x1", "0x2"]},
    )

    assert len(result["results"]) == 2
    assert {item.base_value for item in result["results"]} == {1, 2}
    assert {
        item.hash_value_unsigned_int for item in result["results"]
    } == {
        (_payouts_king_crc32(b"GetProcAddress") + 1) & 0xFFFFFFFF,
        (_payouts_king_crc32(b"GetProcAddress") + 2) & 0xFFFFFFFF,
    }


def test_service_hash_string_for_algorithm_returns_aggregate_results_for_multiple_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    service = ApiHashService.from_project_root(tmp_path)

    result = service.hash_string_for_algorithm(
        algorithm_id="payouts_king_crc32",
        symbol_name="GetProcAddress",
        library_name="kernel32.dll",
        algorithm_params={"base_values": ["0x1", "0x2"]},
    )

    assert isinstance(result, HashStringAggregateResult)
    assert result.algorithm_id == "payouts_king_crc32"
    assert result.library_name == "kernel32.dll"
    assert result.symbol_name == "GetProcAddress"
    assert len(result.results) == 2
    assert {item.base_value for item in result.results} == {1, 2}
    assert {
        item.hash_value_unsigned_int for item in result.results
    } == {
        (_payouts_king_crc32(b"GetProcAddress") + 1) & 0xFFFFFFFF,
        (_payouts_king_crc32(b"GetProcAddress") + 2) & 0xFFFFFFFF,
    }


def test_service_export_enum_for_library_returns_multiple_exports_for_multiple_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    service = ApiHashService.from_project_root(tmp_path)

    result = service.export_enum_for_library(
        algorithm_id="payouts_king_crc32",
        library_name="kernel32.dll",
        algorithm_params={"base_values": ["0x1", "0x2"]},
    )

    assert isinstance(result, ExportedHeaderAggregateResult)
    assert result.algorithm_id == "payouts_king_crc32"
    assert result.library_name == "kernel32.dll"
    assert len(result.results) == 2
    assert [item.library for item in result.results] == ["kernel32.dll", "kernel32.dll"]
    assert {item.base_value for item in result.results} == {1, 2}


def test_service_singular_helpers_return_models_for_single_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    service = ApiHashService.from_project_root(tmp_path)

    hashed = service.hash_string_for_algorithm(
        algorithm_id="payouts_king_crc32",
        symbol_name="GetProcAddress",
        library_name="kernel32.dll",
        algorithm_params={"base_values": ["0x1"]},
    )
    exported = service.export_enum_for_library(
        algorithm_id="payouts_king_crc32",
        library_name="kernel32.dll",
        algorithm_params={"base_values": ["0x1"]},
    )

    assert isinstance(hashed, HashStringResult)
    assert hashed.base_value == 1
    assert isinstance(exported, ExportedHeaderResult)
    assert exported.base_value == 1


def test_service_rejects_mixed_base_and_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    service = ApiHashService.from_project_root(tmp_path)

    try:
        service.hash_string_for_algorithm(
            algorithm_id="payouts_king_crc32",
            symbol_name="GetProcAddress",
            library_name="kernel32.dll",
            algorithm_params={"base": "0x1", "base_values": ["0x2"]},
        )
    except ValueError as exc:
        assert "base" in str(exc)
        assert "base_values" in str(exc)
    else:
        raise AssertionError("Expected ValueError for mixed base and base_values")


def test_service_bulk_auto_export_keeps_matched_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    service = ApiHashService.from_project_root(tmp_path)
    target = (_payouts_king_crc32(b"CreateFileW") + 0x10) & 0xFFFFFFFF

    result = service.bulk_auto_export(
        hash_value=target,
        algorithm_id="payouts_king_crc32",
        library_names=["kernel32.dll"],
        catalog_names=["kernel32.dll"],
        algorithm_params={"base_values": ["0x10", "0x20"]},
    )

    assert len(result["matches"]) == 1
    assert result["matches"][0].base_value == 16
    assert len(result["exports"]) == 1
    assert result["exports"][0].base_value == 16


def test_create_app_exposes_service_instance() -> None:
    project_root = Path(__file__).resolve().parents[1]

    app = create_app(project_root)

    assert hasattr(app.state, "service")
    assert isinstance(app.state.service, ApiHashService)


def test_service_ignores_non_pack_entries_in_packs_directory(tmp_path: Path) -> None:
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()
    (packs_dir / "README.md").write_text("pack docs", encoding="utf-8")
    pack_dir = packs_dir / "sample-pack"
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "algorithms" / "python" / "sample.hash.py").write_text(
        textwrap.dedent(
            '''
            from apihashing.plugin_api import FunctionHashImplementation

            def _hash(library_name: str, symbol_name: str) -> int:
                return 1

            HASH_IMPLEMENTATION = FunctionHashImplementation(
                id="sample_hash",
                display_name="Sample Hash",
                callback=_hash,
                hash_size_bits=32,
            )
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    service = ApiHashService.from_project_root(tmp_path)

    assert [pack.name for pack in service.packs] == ["sample-pack"]
    assert {item.id for item in service.list_algorithms()} == {"sample_hash"}


def test_default_pack_only_registers_local_payouts_demo_and_hashdb_pack_marks_flare_lineage() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    algorithms = service.list_algorithms()
    by_id = {item.id: item for item in algorithms}

    assert by_id["payouts_king_crc32"].pack == "default-pack"
    assert by_id["payouts_king_crc32"].copied_from_flare_shellcode is False
    assert by_id["ror13_add"].pack == "oalabs-hashdb"
    assert by_id["ror13_add"].copied_from_flare_shellcode is True
    assert by_id["conti"].copied_from_flare_shellcode is True


def test_default_pack_loads_payouts_king_wordlists_and_xz_catalogs() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    catalogs = {(item.kind, item.library): item for item in service.list_catalogs()}

    assert (None, "kernel32.dll") in catalogs
    assert catalogs[(None, "kernel32.dll")].source_path is not None
    assert str(catalogs[(None, "kernel32.dll")].source_path).endswith("system32.json.xz")
    assert ("wordlist", "payouts_king_wordlist") in catalogs
    assert len(catalogs[("wordlist", "payouts_king_wordlist")].symbols) == 304
    assert catalogs[("wordlist", "payouts_king_wordlist")].source_path is not None
    assert str(catalogs[("wordlist", "payouts_king_wordlist")].source_path).endswith(".json.xz")


def test_hashdb_flare_lineage_algorithms_resolve_known_kernel32_symbol() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    expected_hashes = {
        "ror13_add": 2080380859,
        "rol7_add": 3539932924,
        "conti": 1187380203,
    }

    for algorithm_id, hash_value in expected_hashes.items():
        result = service.resolve_hash(hash_value, algorithm_id=algorithm_id)
        assert any(
            match.library == "kernel32.dll" and match.symbol == "CreateFileW"
            for match in result.matches
        ), algorithm_id


def test_wordlists_participate_in_searches() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    result = service.search_hash_across_algorithms(_payouts_king_crc32(b"-backup"))

    assert any(
        item.algorithm_id == "payouts_king_crc32"
        and item.catalog_kind == "wordlist"
        and item.library == "payouts_king_wordlist"
        and item.symbol == "-backup"
        for item in result.results
    )


def test_service_supports_three_argument_hash_callbacks_with_algorithm_params(tmp_path: Path) -> None:
    pack_dir = tmp_path / "packs" / "param-pack"
    (pack_dir / "catalogs").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "symbols.json").write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "param_crc.py").write_text(
        textwrap.dedent(
            """
            import zlib

            from apihashing.plugin_api import FunctionHashImplementation


            def _hash(library_name: str, symbol_name: str, params: dict[str, object]) -> int:
                base = int(params.get("base", 0))
                data = f"{library_name}{symbol_name}".encode("utf-8")
                return (zlib.crc32(data) + base) & 0xFFFFFFFF


            HASH_IMPLEMENTATION = FunctionHashImplementation(
                id="param_crc32",
                callback=_hash,
                hash_size_bits=32,
            )
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    service = ApiHashService.from_project_root(tmp_path)
    base = 0x1000
    result = service.hash_string_for_algorithm(
        "param_crc32",
        "DemoExport",
        "demo.dll",
        algorithm_params={"base": "0x1000"},
    )
    resolved = service.resolve_hash(
        result.hash_value_unsigned_int,
        "param_crc32",
        algorithm_params={"base": base},
    )

    assert result.hash_value_unsigned_int == ((zlib.crc32(b"demo.dllDemoExport") & 0xFFFFFFFF) + base) & 0xFFFFFFFF
    assert len(resolved.matches) == 1
    assert resolved.matches[0].symbol == "DemoExport"


def test_service_discovers_hash_plugin_without_yaml_and_supports_64_bit_values(tmp_path: Path) -> None:
    pack_dir = tmp_path / "packs" / "wide-pack"
    (pack_dir / "catalogs" / "pe").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "pe" / "wide.json").write_text(
        '{"library":"wide.dll","symbols":["WideFunction"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "wide64.hash.py").write_text(
        textwrap.dedent(
            '''
            from apihashing.plugin_api import FunctionHashImplementation, HashValue

            def _hash(library_name: str, symbol_name: str) -> HashValue:
                value = 0x123456789ABCDEF0
                return HashValue.from_int(value, bit_length=64)

            HASH_IMPLEMENTATION = FunctionHashImplementation(
                id="wide64",
                display_name="Wide 64",
                callback=_hash,
                hash_size_bits=64,
                description="64-bit example",
            )
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    service = ApiHashService.from_project_root(tmp_path)
    result = service.resolve_hash("0x123456789ABCDEF0", algorithm_id="wide64")

    assert len(result.matches) == 1
    assert result.matches[0].hash_size_bits == 64
    assert result.matches[0].hash_value_hex == "123456789abcdef0"
    assert result.matches[0].hash_value_unsigned_int == 0x123456789ABCDEF0


def test_service_loads_minimal_single_file_plugin_with_optional_metadata_defaults(tmp_path: Path) -> None:
    pack_dir = tmp_path / "packs" / "minimal-pack"
    (pack_dir / "catalogs").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "symbols.json").write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "demo.hash.py").write_text(
        textwrap.dedent(
            '''
            from apihashing.plugin_api import FunctionHashImplementation

            def _hash(library_name: str, symbol_name: str) -> int:
                return 0x11223344

            HASH_IMPLEMENTATION = FunctionHashImplementation(
                id="demo_hash",
                callback=_hash,
            )
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    service = ApiHashService.from_project_root(tmp_path)
    metadata = next(item for item in service.list_algorithms() if item.id == "demo_hash")
    result = service.resolve_hash("0x11223344", algorithm_id="demo_hash")

    assert metadata.display_name == "demo_hash"
    assert metadata.description == ""
    assert metadata.hash_size_bits == 32
    assert len(result.matches) == 1
    assert result.matches[0].library == "demo.dll"


def test_service_loads_hashdb_style_single_file_algorithm(tmp_path: Path) -> None:
    pack_dir = tmp_path / "packs" / "hashdb-pack"
    (pack_dir / "catalogs").mkdir(parents=True)
    (pack_dir / "algorithms" / "python").mkdir(parents=True)
    (pack_dir / "catalogs" / "symbols.json").write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding="utf-8",
    )
    (pack_dir / "algorithms" / "python" / "demo_hashdb.py").write_text(
        textwrap.dedent(
            '''
            DESCRIPTION = "HashDB-style test module"
            TYPE = "unsigned_int"
            TEST_1 = 0xAABBCCDD
            SOURCE = "https://example.test/demo_hashdb.py"
            LICENSE = "Apache-2.0"

            def hash(data):
                return 0xAABBCCDD
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    service = ApiHashService.from_project_root(tmp_path)
    metadata = next(item for item in service.list_algorithms() if item.id == "demo_hashdb")
    result = service.resolve_hash("0xAABBCCDD", algorithm_id="demo_hashdb")

    assert metadata.display_name == "demo_hashdb"
    assert metadata.hash_size_bits == 32
    assert metadata.source == "https://example.test/demo_hashdb.py"
    assert metadata.license == "Apache-2.0"
    assert len(result.matches) == 1


def test_service_applies_xor_modifier_to_search_and_hash_string() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)
    base = _payouts_king_crc32(b"CreateFileW")
    xor_value = 0x13579BDF
    obfuscated = base ^ xor_value

    search = service.search_hash_across_algorithms(obfuscated, xor_value=xor_value)
    hashed = service.hash_string_for_algorithm(
        algorithm_id="payouts_king_crc32",
        symbol_name="CreateFileW",
        library_name="kernel32.dll",
        xor_value=xor_value,
    )

    assert any(item.algorithm_id == "payouts_king_crc32" and item.symbol == "CreateFileW" for item in search.results)
    assert hashed.hash_value_unsigned_int == obfuscated


def test_service_searches_hash_across_all_algorithms() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    result = service.search_hash_across_algorithms(2080380859)

    assert result.query_hash_unsigned_int == 2080380859
    assert len(result.results) >= 1
    assert any(item.algorithm_id == "ror13_add" for item in result.results)


def test_service_search_hash_restricts_to_requested_algorithm() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    result = service.search_hash_across_algorithms(
        2080380859,
        algorithm_id="ror13_add",
        library_filter="kernel32",
    )

    assert result.algorithm_count == 1
    assert result.results
    assert {item.algorithm_id for item in result.results} == {"ror13_add"}


def test_service_loads_oalabs_hashdb_pack_and_crc32_algorithm() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    pack_names = {pack.name for pack in service.packs}
    metadata = next(item for item in service.list_algorithms() if item.id == "crc32")
    hashed = service.hash_string_for_algorithm("crc32", "CreateFileW")

    assert "oalabs-hashdb" in pack_names
    assert metadata.pack == "oalabs-hashdb"
    assert metadata.author == "OALabs/hashdb contributors"
    assert metadata.license == "Apache-2.0"
    assert metadata.source == "https://github.com/OALabs/hashdb/blob/main/algorithms/crc32.py"
    assert hashed.hash_value_unsigned_int == zlib.crc32(b"CreateFileW") & 0xFFFFFFFF


def test_service_hashes_requested_string_for_algorithm() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    result = service.hash_string_for_algorithm(
        algorithm_id="payouts_king_crc32",
        symbol_name="GetProcAddress",
        library_name="kernel32.dll",
    )

    assert result.algorithm_id == "payouts_king_crc32"
    assert result.hash_value_hex == f"{_payouts_king_crc32(b'GetProcAddress'):08x}"


def test_service_builds_merged_catalog_from_binaries() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)
    shared_library = Path("/lib64/libc.so.6")

    merged = service.build_catalogs_from_binaries([
        ("libc.so.6", shared_library.read_bytes()),
        ("libc-copy.so.6", shared_library.read_bytes()),
    ])

    assert len(merged.libraries) == 2
    assert merged.libraries[0].library == "libc.so.6"
    assert merged.libraries[1].library == "libc-copy.so.6"
    assert merged.libraries[0].symbols
    assert merged.libraries[0].binary_family in {"elf", "pe", "macho"}


def test_service_builds_merged_catalog_from_binaries_skips_non_dll_pe_inputs() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    def fake_build_catalog_from_binary_blob(filename: str, blob: bytes) -> CatalogRecord:
        del blob
        lowered = filename.lower()
        if lowered.endswith(".dll"):
            family = "pe"
        elif lowered.endswith(".exe") or lowered.endswith(".sys"):
            family = "pe"
        else:
            family = "elf"
        return CatalogRecord(
            kind=None,
            binary_family=family,
            library=filename,
            symbols=["DemoExport"],
        )

    with patch("apihashing.core.service.build_catalog_from_binary_blob", side_effect=fake_build_catalog_from_binary_blob):
        merged = service.build_catalogs_from_binaries(
            [
                ("kernel32.dll", b"dll"),
                ("notepad.exe", b"exe"),
                ("driver.sys", b"sys"),
                ("libc.so.6", b"so"),
            ]
        )

    assert {entry.library for entry in merged.libraries} == {"kernel32.dll", "libc.so.6"}


def test_service_builds_catalogs_from_paths_skips_non_dll_pe_inputs(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    for name in ("kernel32.dll", "notepad.exe", "driver.sys", "libc.so.6"):
        (sample_dir / name).write_bytes(b"stub")

    def fake_build_catalog_from_binary_path(binary_path: Path) -> CatalogRecord:
        lowered = binary_path.name.lower()
        if lowered.endswith(".dll"):
            family = "pe"
        elif lowered.endswith(".exe") or lowered.endswith(".sys"):
            family = "pe"
        else:
            family = "elf"
        return CatalogRecord(
            kind=None,
            binary_family=family,
            library=binary_path.name,
            symbols=["DemoExport"],
        )

    with patch("apihashing.core.service.build_catalog_from_binary_path", side_effect=fake_build_catalog_from_binary_path):
        merged = service.build_catalogs_from_paths([sample_dir], max_workers=1)

    assert {entry.library for entry in merged.libraries} == {"kernel32.dll", "libc.so.6"}


def test_service_search_hash_in_catalogs_runs_algorithms_multithreaded() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)
    active_pack = next(iter(service.active_pack_names))

    fake_algorithms = [
        AlgorithmMetadata(
            id="alg_one",
            display_name="alg_one",
            implementation_type="python",
            input_mode="symbol_only",
            hash_size_bits=32,
            pack=active_pack,
            module_path="alg_one.py",
        ),
        AlgorithmMetadata(
            id="alg_two",
            display_name="alg_two",
            implementation_type="python",
            input_mode="symbol_only",
            hash_size_bits=32,
            pack=active_pack,
            module_path="alg_two.py",
        ),
    ]
    seen_threads: set[int] = set()
    seen_lock = threading.Lock()

    def fake_collect(*args, **kwargs):
        del args, kwargs
        time.sleep(0.03)
        with seen_lock:
            seen_threads.add(threading.get_ident())
        return []

    class _FakeLoaded:
        def __init__(self, metadata: AlgorithmMetadata) -> None:
            self.metadata = metadata

    with (
        patch.object(service.registry, "list", return_value=fake_algorithms),
        patch.object(
            service.registry,
            "get",
            side_effect=lambda algorithm_id: _FakeLoaded(next(item for item in fake_algorithms if item.id == algorithm_id)),
        ),
        patch.object(service, "_collect_matches_for_algorithm", side_effect=fake_collect),
    ):
        service.search_hash_in_catalogs(
            0,
            catalogs=[CatalogRecord(kind=None, binary_family="pe", library="kernel32.dll", symbols=["CreateFileW"])],
        )

    assert len(seen_threads) >= 2


def test_service_searches_hash_with_library_filter() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    filtered = service.search_hash_across_algorithms(2080380859, library_filter="kernel32")
    missing = service.search_hash_across_algorithms(2080380859, library_filter="ntdll")

    assert any(item.library == "kernel32.dll" for item in filtered.results)
    assert missing.results == []


def test_service_catalog_selection_defaults_to_active_catalogs_and_respects_requested_catalog_names() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    active_catalogs = service.get_catalogs_for_query()
    selected_catalogs = service.get_catalogs_for_query(catalog_names=["kernel32.dll"])

    assert any(catalog.library == "kernel32.dll" for catalog in active_catalogs)
    assert {catalog.library for catalog in selected_catalogs} == {"kernel32.dll"}


def test_service_common_windows_scope_implies_hyphen_exclusion() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    catalogs = service.list_catalogs(common_windows_dlls_only=True)

    assert any(catalog.library == "kernel32.dll" for catalog in catalogs)
    assert not any(catalog.kind != "wordlist" and "-" in catalog.library for catalog in catalogs)


def test_service_toggles_pack_activation_for_current_process_only() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)

    assert all(pack["active"] is True for pack in service.list_packs())
    assert any(item.id == "payouts_king_crc32" for item in service.list_algorithms())

    service.set_pack_active("default-pack", False)
    active_catalogs = service.get_catalogs_for_query()
    active_algorithms = service.list_algorithms()

    assert any(pack["name"] == "default-pack" and pack["active"] is False for pack in service.list_packs())
    assert not any(catalog.library == "kernel32.dll" for catalog in active_catalogs)
    assert not any(item.id == "payouts_king_crc32" for item in active_algorithms)
    with pytest.raises(ValueError):
        service.hash_string_for_algorithm("payouts_king_crc32", "CreateFileW", "kernel32.dll")


def test_service_bulk_export_groups_matches_by_library_and_renders_headers() -> None:
    project_root = Path(__file__).resolve().parents[1]
    service = ApiHashService.from_project_root(project_root)
    target = _payouts_king_crc32(b"CreateFileW")

    result = service.bulk_auto_export(
        hash_value=target,
        algorithm_id="payouts_king_crc32",
        library_names=["kernel32.dll"],
        catalog_names=["kernel32.dll"],
    )

    assert any(match.library == "kernel32.dll" and match.symbol == "CreateFileW" for match in result["matches"])
    assert result["exports"][0].library == "kernel32.dll"
    assert "CreateFileW" in result["exports"][0].header_text
