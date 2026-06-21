import asyncio
import io
import json
import os
import subprocess
import sys
import zlib
from pathlib import Path
from unittest.mock import patch

import httpx

from apihashing.app import create_app
from apihashing.cli import _progress_renderer


async def _request(app, method: str, url: str, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as client:
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
    pack_dir = root / 'packs' / 'param-pack'
    (pack_dir / 'catalogs').mkdir(parents=True)
    (pack_dir / 'algorithms' / 'python').mkdir(parents=True)
    (pack_dir / 'catalogs' / 'symbols.json').write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding='utf-8',
    )
    (pack_dir / 'algorithms' / 'python' / 'param_crc.py').write_text(
        """
import zlib
from apihashing.plugin_api import FunctionHashImplementation

def _hash(library_name, symbol_name, params):
    base = int(params.get("base", 0))
    return (zlib.crc32(f"{library_name}{symbol_name}".encode("utf-8")) + base) & 0xFFFFFFFF

HASH_IMPLEMENTATION = FunctionHashImplementation(id="param_crc32", callback=_hash, hash_size_bits=32)
""".lstrip(),
        encoding='utf-8',
    )


def test_cli_algorithms_lists_ids_by_default() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, '-m', 'apihashing', 'algorithms'],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    assert 'payouts_king_crc32' in lines
    assert 'ror13_add' in lines
    assert not result.stdout.lstrip().startswith('[')


def test_cli_algorithms_works_without_local_packs_via_bundled_defaults(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    existing = env.get('PYTHONPATH', '')
    env['PYTHONPATH'] = f'{project_root}:{existing}' if existing else str(project_root)
    result = subprocess.run(
        [sys.executable, '-m', 'apihashing', 'algorithms'],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    assert 'payouts_king_crc32' in lines


def test_cli_algorithms_verbose_outputs_json() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, '-m', 'apihashing', 'algorithms', '-v'],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert any(item['id'] == 'payouts_king_crc32' for item in payload)


def test_api_searches_hash_with_library_filter() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            'POST',
            '/search-hash',
            json={'hash_value': '0x7c0017bb', 'library_name': 'kernel32'},
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload['library_filter'] == 'kernel32'
    assert all('kernel32' in item['library'].lower() for item in payload['results'])


def test_api_searches_hash_with_common_windows_filters() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            'POST',
            '/search-hash',
            json={
                'hash_value': '0x7c0017bb',
                'exclude_hyphenated_dlls': True,
                'common_windows_dlls_only': True,
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert any(item['library'] == 'kernel32.dll' for item in payload['results'])
    assert not any('-' in item['library'] for item in payload['results'])


def test_api_exports_c_header_enum() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(
        _request(
            app,
            'POST',
            '/export-enum',
            json={'algorithm_id': 'payouts_king_crc32', 'library_name': 'kernel32.dll'},
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload['library'] == 'kernel32.dll'
    assert 'apihashing_payouts_king_crc32_kernel32_dll_CreateFileW' in payload['header_text']


def test_cli_hashes_string_and_emits_json() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'hash-string',
            '--algorithm',
            'payouts_king_crc32',
            '--symbol',
            'GetProcAddress',
            '--library',
            'kernel32.dll',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload['algorithm_id'] == 'payouts_king_crc32'
    assert payload['results'][0]['hash_value_hex'] == f'{_payouts_king_crc32(b"GetProcAddress"):08x}'


def test_cli_hashes_multiple_symbols_and_libraries() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'hash-string',
            '--algorithm',
            'payouts_king_crc32',
            '--library',
            'kernel32.dll,user32.dll',
            '--symbol',
            'GetProcAddress,LoadLibraryA',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload['libraries'] == ['kernel32.dll', 'user32.dll']
    assert payload['symbols'] == ['GetProcAddress', 'LoadLibraryA']
    assert len(payload['results']) == 2
    assert all(item['library_name'] == '' for item in payload['results'])


def test_cli_hashes_string_with_algorithm_params(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    pack_dir = tmp_path / 'packs' / 'param-pack'
    (pack_dir / 'catalogs').mkdir(parents=True)
    (pack_dir / 'algorithms' / 'python').mkdir(parents=True)
    (pack_dir / 'catalogs' / 'symbols.json').write_text(
        '{"library":"demo.dll","symbols":["DemoExport"]}',
        encoding='utf-8',
    )
    (pack_dir / 'algorithms' / 'python' / 'param_crc.py').write_text(
        'import zlib\n'
        'from apihashing.plugin_api import FunctionHashImplementation\n\n'
        'def _hash(library_name, symbol_name, params):\n'
        '    base = int(params.get("base", 0))\n'
        '    return (zlib.crc32(f"{library_name}{symbol_name}".encode("utf-8")) + base) & 0xFFFFFFFF\n\n'
        'HASH_IMPLEMENTATION = FunctionHashImplementation(id="param_crc32", callback=_hash, hash_size_bits=32)\n',
        encoding='utf-8',
    )

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            '--project-root',
            str(tmp_path),
            'hash-string',
            '--algorithm',
            'param_crc32',
            '--symbol',
            'DemoExport',
            '--library',
            'demo.dll',
            '--param',
            'base=0x1000',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload['results'][0]['hash_value_unsigned_int'] == ((zlib.crc32(b'demo.dllDemoExport') & 0xFFFFFFFF) + 0x1000) & 0xFFFFFFFF


def test_cli_hash_string_accepts_repeated_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            '--project-root',
            str(tmp_path),
            'hash-string',
            '--algorithm',
            'param_crc32',
            '--symbol',
            'DemoExport',
            '--library',
            'demo.dll',
            '--base',
            '0x10',
            '--base',
            '0x20',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert [(item['library_name'], item['base_value']) for item in payload['results']] == [
        ('demo.dll', 16),
        ('demo.dll', 32),
    ]


def test_cli_search_hash_accepts_comma_separated_base_values(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    project_root = Path(__file__).resolve().parents[1]
    base_hash = zlib.crc32(b'demo.dllDemoExport') & 0xFFFFFFFF

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            '--project-root',
            str(tmp_path),
            'search-hash',
            '--hash',
            hex((base_hash + 0x20) & 0xFFFFFFFF),
            '--dll',
            'demo.dll',
            '--base',
            '0x10,0x20',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert [item['base_value'] for item in payload['results']] == [32]
    assert payload['results'][0]['library'] == 'demo.dll'


def test_cli_export_enum_accepts_comma_separated_base_values_and_returns_aggregate_json(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            '--project-root',
            str(tmp_path),
            'export-enum',
            '--algorithm',
            'param_crc32',
            '--dll',
            'demo.dll',
            '--base',
            '0x10,0x20',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload['algorithm_id'] == 'param_crc32'
    assert payload['library_name'] == 'demo.dll'
    assert [item['base_value'] for item in payload['results']] == [16, 32]


def test_cli_bulk_auto_accepts_repeated_base_values_and_preserves_base_value_attribution(tmp_path: Path) -> None:
    _write_multibase_test_pack(tmp_path)
    project_root = Path(__file__).resolve().parents[1]
    target = ((zlib.crc32(b'demo.dllDemoExport') & 0xFFFFFFFF) + 0x20) & 0xFFFFFFFF

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            '--project-root',
            str(tmp_path),
            'bulk-auto',
            '--algorithm',
            'param_crc32',
            '--hash',
            hex(target),
            '--dll',
            'demo.dll',
            '--base',
            '0x10',
            '--base',
            '0x20',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert [(item['library'], item['base_value']) for item in payload['matches']] == [('demo.dll', 32)]
    assert [(item['library'], item['base_value']) for item in payload['exports']] == [('demo.dll', 32)]


def test_cli_builds_catalog_from_local_path() -> None:
    project_root = Path(__file__).resolve().parents[1]
    shared_library = '/lib64/libc.so.6'

    result = subprocess.run(
        [sys.executable, '-m', 'apihashing', 'build-catalog', '--input', shared_library],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload['libraries'][0]['library'] == 'libc.so.6'
    assert payload['libraries'][0]['symbols']
    assert 'kind' not in payload['libraries'][0]


def test_cli_builds_catalog_recursively_from_local_path(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    nested = tmp_path / 'level1' / 'level2'
    nested.mkdir(parents=True)
    sample = nested / 'libc.so.6'
    sample.write_bytes(Path('/lib64/libc.so.6').read_bytes())

    result = subprocess.run(
        [sys.executable, '-m', 'apihashing', 'build-catalog', '--input', str(tmp_path)],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert any(item['library'] == 'libc.so.6' for item in payload['libraries'])



def test_cli_builds_catalog_to_xz_output(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    output_path = tmp_path / 'catalog.json.xz'

    subprocess.run(
        [sys.executable, '-m', 'apihashing', 'build-catalog', '--input', '/lib64/libc.so.6', '--output', str(output_path)],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    import lzma
    payload = json.loads(lzma.decompress(output_path.read_bytes()).decode('utf-8'))
    assert payload['libraries'][0]['library'] == 'libc.so.6'

def test_cli_exports_enum_header_text() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'export-enum',
            '--algorithm',
            'payouts_king_crc32',
            '--dll',
            'kernel32.dll',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'typedef enum {' in result.stdout
    assert 'apihashing_payouts_king_crc32_kernel32_dll_CreateFileW' in result.stdout


def test_cli_help_is_descriptive() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, '-m', 'apihashing', '--help'],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'Local API hashing CLI for malware analysis workflows.' in result.stdout
    assert 'apihashing init --workspace ./apihashing-workspace --pack-name team-pack' in result.stdout
    assert 'hash-string --algorithm payouts_king_crc32 --library kernel32.dll,user32.dll' in result.stdout
    assert 'build-catalog --input ~/vmtransit/readwrite/System32' in result.stdout


def test_progress_renderer_clears_leftover_filename_tail() -> None:
    stream = io.StringIO()
    render = _progress_renderer('Building catalogs')

    with patch('apihashing.cli.sys.stderr', stream):
        render(1, 2, Path('this_is_a_very_long_filename.dll'))
        render(2, 2, Path('short.dll'))

    output = stream.getvalue()
    assert '\rBuilding catalogs [###############---------------] 1/2 this_is_a_very_long_filename.dll' in output
    assert '\rBuilding catalogs [##############################] 2/2 short.dll' in output
    final_line = output.split('\r')[-1]
    assert 'this_is_a_very_long_filename.dll' not in final_line


def test_cli_search_hash_restricts_results_to_requested_catalogs() -> None:
    project_root = Path(__file__).resolve().parents[1]
    target = _payouts_king_crc32(b'CreateFileW')

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'search-hash',
            '--hash',
            hex(target),
            '--dll',
            'kernel32.dll',
            '--catalog',
            'kernel32.dll',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload['library_names'] == ['kernel32.dll']
    assert all(item['library'] == 'kernel32.dll' for item in payload['results'])


def test_cli_search_hash_accepts_optional_algorithm_filter() -> None:
    project_root = Path(__file__).resolve().parents[1]
    target = _payouts_king_crc32(b'CreateFileW')

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'search-hash',
            '--hash',
            hex(target),
            '--dll',
            'kernel32.dll',
            '--algorithm',
            'payouts_king_crc32',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert payload['algorithm_count'] == 1
    assert payload['results']
    assert {item['algorithm_id'] for item in payload['results']} == {'payouts_king_crc32'}


def test_cli_export_enum_restricts_to_requested_catalogs() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'export-enum',
            '--algorithm',
            'payouts_king_crc32',
            '--dll',
            'kernel32.dll',
            '--catalog',
            'kernel32.dll',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'apihashing_payouts_king_crc32_kernel32_dll_CreateFileW' in result.stdout


def test_cli_bulk_auto_emits_matches_and_rendered_enums() -> None:
    project_root = Path(__file__).resolve().parents[1]
    target = _payouts_king_crc32(b'CreateFileW')

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'bulk-auto',
            '--algorithm',
            'payouts_king_crc32',
            '--hash',
            hex(target),
            '--dll',
            'kernel32.dll',
            '--catalog',
            'kernel32.dll',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert any(item['library'] == 'kernel32.dll' for item in payload['matches'])
    assert payload['exports'][0]['library'] == 'kernel32.dll'


def test_cli_searches_hash_with_input_path() -> None:
    project_root = Path(__file__).resolve().parents[1]
    target = _payouts_king_crc32(b'printf')

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'search-hash',
            '--hash',
            hex(target),
            '--input',
            '/lib64/libc.so.6',
            '--dll',
            'libc.so.6',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert any(item['library'] == 'libc.so.6' for item in payload['results'])


def test_cli_search_hash_supports_library_scope_flags(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    catalog_path = tmp_path / 'scope_catalog.json'
    catalog_path.write_text(
        json.dumps(
            {
                'libraries': [
                    {'library': 'kernel32.dll', 'symbols': ['CreateFileW']},
                    {'library': 'api-ms-win-core-file-l1-2-0.dll', 'symbols': ['CreateFileW']},
                ]
            }
        ),
        encoding='utf-8',
    )

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'search-hash',
            '--hash',
            str(_payouts_king_crc32(b'CreateFileW')),
            '--catalog-json',
            str(catalog_path),
            '--exclude-hyphenated-dlls',
            '--common-windows-dlls-only',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert any(item['library'] == 'kernel32.dll' for item in payload['results'])
    assert not any('-' in item['library'] for item in payload['results'])


def test_cli_exports_enum_from_input_path() -> None:
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'export-enum',
            '--algorithm',
            'payouts_king_crc32',
            '--dll',
            'libc.so.6',
            '--input',
            '/lib64/libc.so.6',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'typedef enum {' in result.stdout
    assert 'apihashing_payouts_king_crc32_libc_so_6_' in result.stdout


def test_cli_init_creates_new_pack_workspace_without_bundled_packs(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    workspace = tmp_path / 'workspace'

    result = subprocess.run(
        [
            sys.executable,
            '-m',
            'apihashing',
            'init',
            '--workspace',
            str(workspace),
            '--pack-name',
            'team-pack',
            '--no-bundled-packs',
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    pack_root = workspace / 'packs' / 'team-pack'
    assert pack_root.exists()
    assert (pack_root / 'algorithms' / 'python').exists()
    assert (pack_root / 'algorithms' / 'native').exists()
    assert (pack_root / 'catalogs' / 'pe').exists()
    assert (pack_root / 'catalogs' / 'wordlists').exists()
    assert (pack_root / 'tests').exists()
    assert 'git init' in result.stdout
    assert 'git submodule add' in result.stdout
