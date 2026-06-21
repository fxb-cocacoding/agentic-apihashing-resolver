from __future__ import annotations

import argparse
import json
import lzma
import os
import sys
from pathlib import Path
from typing import Callable

from apihashing.core.models import CatalogRecord
from apihashing.core.pack_loader import PackLoader
from apihashing.core.service import ApiHashService
from apihashing.core.workspace import init_workspace


def _project_root(value: str | None) -> Path:
    if value:
        return Path(value).resolve()
    env_value = os.environ.get('APIHASHING_PROJECT_ROOT')
    if env_value:
        return Path(env_value).resolve()
    return Path.cwd()


def _service(project_root: Path) -> ApiHashService:
    return ApiHashService.from_project_root(project_root)


def _load_catalogs(catalog_json: str | None) -> list[CatalogRecord] | None:
    if not catalog_json:
        return None
    catalog_path = Path(catalog_json)
    if catalog_path.name.endswith('.json.xz'):
        payload = json.loads(lzma.decompress(catalog_path.read_bytes()).decode('utf-8'))
    else:
        payload = json.loads(catalog_path.read_text(encoding='utf-8'))
    libraries = payload.get('libraries', []) if isinstance(payload, dict) else payload
    return [PackLoader._catalog_record_from_payload(item) for item in libraries]


def _progress_renderer(label: str) -> Callable[[int, int, Path], None]:
    last_length = 0

    def render(completed: int, total: int, current_path: Path) -> None:
        nonlocal last_length
        width = 30
        filled = width if total == 0 else int(width * completed / total)
        bar = f'{"#" * filled}{"-" * (width - filled)}'
        line = f'{label} [{bar}] {completed}/{total} {current_path.name}'
        padding = ' ' * max(0, last_length - len(line))
        sys.stderr.write(f'\r{line}{padding}')
        last_length = len(line)
        if completed >= total:
            sys.stderr.write('\n')
            last_length = 0
        sys.stderr.flush()

    return render


def _catalog_worker_count() -> int:
    return min(32, max(1, (os.cpu_count() or 1) + 4))


def _collect_catalogs(service: ApiHashService, catalog_json: str | None, inputs: list[str] | None, show_progress: bool = False) -> list[CatalogRecord] | None:
    loaded: list[CatalogRecord] = []
    json_catalogs = _load_catalogs(catalog_json)
    if json_catalogs:
        loaded.extend(json_catalogs)
    if inputs:
        worker_count = _catalog_worker_count()
        progress_callback = _progress_renderer(f'Building catalogs <threads: {worker_count}>') if show_progress and sys.stderr.isatty() else None
        loaded.extend(
            service.build_catalogs_from_paths(
                [Path(item) for item in inputs],
                progress_callback=progress_callback,
                max_workers=worker_count,
            ).libraries
        )
    return service.merge_catalogs(loaded) if loaded else None


def _selected_catalogs(
    service: ApiHashService,
    catalog_json: str | None,
    inputs: list[str] | None,
    catalog_names: list[str] | None,
    *,
    show_progress: bool = False,
    exclude_hyphenated_dlls: bool = False,
    common_windows_dlls_only: bool = False,
) -> list[CatalogRecord]:
    transient_catalogs = _collect_catalogs(service, catalog_json, inputs, show_progress=show_progress)
    return service.get_catalogs_for_query(
        transient_catalogs,
        catalog_names=_expand_values(catalog_names),
        exclude_hyphenated_dlls=exclude_hyphenated_dlls,
        common_windows_dlls_only=common_windows_dlls_only,
    )


def _write_output(text: str, output_path: str | None) -> int:
    if output_path:
        path = Path(output_path)
        if path.name.endswith('.xz'):
            path.write_bytes(lzma.compress(text.encode('utf-8')))
        else:
            path.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
        if not text.endswith('\n'):
            sys.stdout.write('\n')
    return 0


def _expand_values(values: list[str] | None) -> list[str]:
    expanded: list[str] = []
    for value in values or []:
        expanded.extend(item.strip() for item in value.split(',') if item.strip())
    return expanded


def _parse_algorithm_params(values: list[str] | None) -> dict[str, object] | None:
    params: dict[str, object] = {}
    for value in values or []:
        key, sep, raw = value.partition('=')
        if not sep or not key.strip():
            raise ValueError(f'Invalid --param value: {value!r}. Use key=value.')
        params[key.strip()] = raw.strip()
    return params or None


def _merge_base_values(params: dict[str, object] | None, base_values: list[str] | None) -> dict[str, object] | None:
    expanded = _expand_values(base_values)
    if not expanded:
        return params
    merged = dict(params or {})
    merged['base_values'] = expanded
    return merged


def _json_ready(value):
    if hasattr(value, 'model_dump'):
        return value.model_dump(mode='json', exclude_none=True)
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    return value


def _library_filters(values: list[str] | None) -> list[str]:
    filters = _expand_values(values)
    return filters or [None]


def _hash_string_payload(service: ApiHashService, algorithm_id: str, symbols: list[str], libraries: list[str]) -> dict[str, object]:
    resolved_libraries = libraries or ['']
    results = [
        service.hash_string_for_algorithm(algorithm_id, symbol_name=symbol, library_name=library, algorithm_params=_parse_algorithm_params([]))
        for library in resolved_libraries
        for symbol in symbols
    ]
    return {
        'algorithm_id': algorithm_id,
        'libraries': resolved_libraries,
        'symbols': symbols,
        'results': [item.model_dump(mode='json') for item in results],
    }


def _search_hash_payload(
    service: ApiHashService,
    hash_value: str,
    library_names: list[str],
    catalogs: list[CatalogRecord],
    algorithm_id: str | None = None,
    xor_value: str | None = None,
    algorithm_params: dict[str, object] | None = None,
    exclude_hyphenated_dlls: bool = False,
    common_windows_dlls_only: bool = False,
) -> dict[str, object]:
    result = service.search_hash_in_catalogs(
        hash_value,
        catalogs,
        algorithm_id=algorithm_id,
        library_names=library_names or None,
        xor_value=xor_value,
        algorithm_params=algorithm_params,
        exclude_hyphenated_dlls=exclude_hyphenated_dlls,
        common_windows_dlls_only=common_windows_dlls_only,
    )
    payload = result.model_dump(mode='json', exclude_none=True)
    payload['library_names'] = library_names
    return payload


def _enum_output(
    service: ApiHashService,
    algorithm_id: str,
    dlls: list[str],
    catalogs: list[CatalogRecord],
    output_path: str | None,
    xor_value: str | None = None,
    algorithm_params: dict[str, object] | None = None,
) -> int:
    if len(dlls) == 1:
        rendered = service.export_enum_for_library(
            algorithm_id,
            dlls[0],
            catalogs=catalogs,
            xor_value=xor_value,
            algorithm_params=algorithm_params,
        )
        if output_path:
            if hasattr(rendered, 'header_text'):
                return _write_output(rendered.header_text, output_path)
            payload = '\n'.join(item.header_text for item in rendered.results)
            return _write_output(payload, output_path)
        if hasattr(rendered, 'header_text'):
            return _write_output(rendered.header_text, None)
        return _write_output(json.dumps(_json_ready(rendered), indent=2), None)

    rendered = service.export_enums_for_libraries(
        algorithm_id,
        dlls,
        catalogs=catalogs,
        xor_value=xor_value,
        algorithm_params=algorithm_params,
    )
    if output_path and len(rendered) > 1:
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        for item in rendered:
            file_name = item.enum_name.lower()
            if item.base_value is not None:
                file_name = f'{file_name}_base_{item.base_value:x}'
            file_name = f'{file_name}.h'
            (output_dir / file_name).write_text(item.header_text, encoding='utf-8')
        return 0
    if len(rendered) > 1:
        payload = {
            'algorithm_id': algorithm_id,
            'libraries': dlls,
            'exports': _json_ready(rendered),
        }
        return _write_output(json.dumps(payload, indent=2), None)
    payload = '\n'.join(item.header_text for item in rendered)
    return _write_output(payload, output_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='apihashing',
        description='Local API hashing CLI for malware analysis workflows.',
        allow_abbrev=False,
        epilog=(
            'Examples:\n'
            '  apihashing algorithms\n'
            '  apihashing init --workspace ./apihashing-workspace --pack-name team-pack\n'
            '  apihashing hash-string --algorithm payouts_king_crc32 --library kernel32.dll --symbol GetProcAddress\n'
            '  apihashing hash-string --algorithm payouts_king_crc32 --library kernel32.dll,user32.dll --symbol GetProcAddress,LoadLibraryA\n'
            '  apihashing search-hash --hash 0x7c0017bb --dll kernel32 --dll ntdll\n'
            '  apihashing build-catalog --input ~/vmtransit/readwrite/System32 --output system32.json.xz\n'
            '  apihashing export-enum --algorithm payouts_king_crc32 --dll kernel32.dll --dll user32.dll --output headers/'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--project-root', default=None, help='Project root containing the packs/ directory. Defaults to the current working directory.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    init_cmd = subparsers.add_parser(
        'init',
        help='Initialize a standalone workspace and create a new external pack skeleton.',
        description='Create a workspace with packs/ and one new pack. By default, bundled reference packs are copied for standalone pipx/uv usage.',
    )
    init_cmd.add_argument(
        '--workspace',
        default='.',
        help='Workspace root path to create or reuse. Defaults to the current directory.',
    )
    init_cmd.add_argument(
        '--pack-name',
        required=True,
        help='New pack name to create under packs/. Recommended: lowercase with hyphen.',
    )
    init_cmd.add_argument(
        '--no-bundled-packs',
        action='store_true',
        help='Do not copy bundled reference packs into the workspace.',
    )

    algorithms = subparsers.add_parser(
        'algorithms',
        help='List discovered hash implementation ids. Use -v for full JSON metadata.',
    )
    algorithms.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Show full algorithm metadata as JSON.',
    )

    hash_string = subparsers.add_parser(
        'hash-string',
        help='Hash one or more symbol names with one algorithm.',
        description='Hash one or more symbol names. Repeated --library and --symbol values, or comma-separated values, are expanded into all combinations.',
    )
    hash_string.add_argument('--algorithm', required=True, help='Algorithm id from `apihashing algorithms`.')
    hash_string.add_argument('--symbol', action='append', required=True, help='Symbol name to hash. Repeat or use comma-separated values.')
    hash_string.add_argument('--library', '--dll', action='append', default=[], help='Optional DLL/shared object name. Repeat or use comma-separated values.')
    hash_string.add_argument('--catalog', action='append', default=[], help='Optional catalog name to restrict selected libraries. Repeat or use comma-separated values.')
    hash_string.add_argument('--base', action='append', default=[], help='Optional base value. Repeat or use comma-separated values.')
    hash_string.add_argument('--xor', dest='xor_value', default=None, help='Optional XOR value applied to the final hash output.')
    hash_string.add_argument('--param', action='append', default=[], help='Algorithm-specific parameter in key=value form. Repeat as needed.')

    search_hash = subparsers.add_parser(
        'search-hash',
        help='Search one observed hash across loaded algorithms and catalogs, optionally restricted to one algorithm.',
        description='Search one observed hash value. Repeated --dll/--library values restrict the search to selected libraries.',
    )
    search_hash.add_argument('--hash', dest='hash_value', required=True, help='Observed hash value as decimal or hex string.')
    search_hash.add_argument('--dll', '--library', action='append', default=[], help='Optional DLL/library name filter. Repeat or use comma-separated values.')
    search_hash.add_argument('--catalog', action='append', default=[], help='Optional catalog name to search within. Repeat or use comma-separated values.')
    search_hash.add_argument('--catalog-json', default=None, help='Optional merged catalog JSON produced by build-catalog.')
    search_hash.add_argument('--input', action='append', default=[], help='Optional file or directory path to build transient catalogs from.')
    search_hash.add_argument('--algorithm', default=None, help='Optional algorithm id to restrict search results to one algorithm.')
    search_hash.add_argument('--base', action='append', default=[], help='Optional base value. Repeat or use comma-separated values.')
    search_hash.add_argument('--xor', dest='xor_value', default=None, help='Optional XOR value applied before hash lookup.')
    search_hash.add_argument('--param', action='append', default=[], help='Algorithm-specific parameter in key=value form. Repeat as needed.')
    search_hash.add_argument('--exclude-hyphenated-dlls', action='store_true', help='Skip library catalogs whose DLL/shared-object name contains a hyphen.')
    search_hash.add_argument('--common-windows-dlls-only', action='store_true', help='Restrict search to common Windows API DLLs such as kernel32.dll, user32.dll, kernelbase.dll, and ntdll.dll.')

    build_catalog = subparsers.add_parser(
        'build-catalog',
        help='Build merged catalog JSON from local library files or directories.',
        description='Read one or more library files or directories with PE/ELF/Mach-O shared objects and emit merged catalog JSON. If --output ends with .json.xz, the JSON is written compressed with xz.',
    )
    build_catalog.add_argument('--input', nargs='+', required=True, help='One or more files or directories to scan.')
    build_catalog.add_argument('--output', default=None, help='Optional output file path. Use .json.xz for compressed output. Defaults to stdout.')

    export_enum = subparsers.add_parser(
        'export-enum',
        help='Render one or more libraries as C header enums for a selected algorithm.',
        description='Render C header enums for one or more libraries. Repeated --dll values, or comma-separated values, are supported.',
    )
    export_enum.add_argument('--algorithm', required=True, help='Algorithm id from `apihashing algorithms`.')
    export_enum.add_argument('--dll', '--library', action='append', required=True, help='Library name to export. Repeat or use comma-separated values.')
    export_enum.add_argument('--catalog', action='append', default=[], help='Optional catalog name to export from. Repeat or use comma-separated values.')
    export_enum.add_argument('--catalog-json', default=None, help='Optional merged catalog JSON produced by build-catalog.')
    export_enum.add_argument('--input', action='append', default=[], help='Optional file or directory path to build transient catalogs from.')
    export_enum.add_argument('--output', default=None, help='Optional output file path. If multiple DLLs are requested, this must be a directory.')
    export_enum.add_argument('--base', action='append', default=[], help='Optional base value. Repeat or use comma-separated values.')
    export_enum.add_argument('--xor', dest='xor_value', default=None, help='Optional XOR value applied to exported enum values.')
    export_enum.add_argument('--param', action='append', default=[], help='Algorithm-specific parameter in key=value form. Repeat as needed.')

    bulk_auto = subparsers.add_parser(
        'bulk-auto',
        help='Resolve one observed hash for one algorithm and export enums for matched libraries.',
    )
    bulk_auto.add_argument('--algorithm', required=True, help='Algorithm id from `apihashing algorithms`.')
    bulk_auto.add_argument('--hash', dest='hash_value', required=True, help='Observed hash value as decimal or hex string.')
    bulk_auto.add_argument('--dll', '--library', action='append', default=[], help='Optional DLL/library name filter. Repeat or use comma-separated values.')
    bulk_auto.add_argument('--catalog', action='append', default=[], help='Optional catalog name to search/export within. Repeat or use comma-separated values.')
    bulk_auto.add_argument('--catalog-json', default=None, help='Optional merged catalog JSON produced by build-catalog.')
    bulk_auto.add_argument('--input', action='append', default=[], help='Optional file or directory path to build transient catalogs from.')
    bulk_auto.add_argument('--base', action='append', default=[], help='Optional base value. Repeat or use comma-separated values.')
    bulk_auto.add_argument('--xor', dest='xor_value', default=None, help='Optional XOR value applied before lookup and export.')
    bulk_auto.add_argument('--param', action='append', default=[], help='Algorithm-specific parameter in key=value form. Repeat as needed.')
    bulk_auto.add_argument('--exclude-hyphenated-dlls', action='store_true', help='Skip library catalogs whose DLL/shared-object name contains a hyphen.')
    bulk_auto.add_argument('--common-windows-dlls-only', action='store_true', help='Restrict search to common Windows API DLLs.')

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == 'init':
        try:
            result = init_workspace(
                Path(args.workspace),
                pack_name=args.pack_name,
                include_bundled_packs=not args.no_bundled_packs,
            )
        except ValueError as exc:
            parser.error(str(exc))
        bundled_packs = [path.name for path in result.copied_bundled_pack_paths]
        lines = [
            f'Workspace: {result.workspace_root}',
            f'Packs root: {result.packs_root}',
            f'Created pack: {result.created_pack_path}',
        ]
        if bundled_packs:
            lines.append(f'Copied bundled packs: {", ".join(bundled_packs)}')
        else:
            lines.append('Copied bundled packs: none')
        lines.extend(
            [
                '',
                'Suggested separation workflow:',
                f'  cd {result.created_pack_path}',
                '  git init',
                '  # push this pack to its own repository',
                '',
                'Then in your core apihashing repository:',
                f'  git submodule add <pack-repo-url> packs/{result.created_pack_path.name}',
            ]
        )
        return _write_output('\n'.join(lines), None)

    service = _service(_project_root(args.project_root))

    if args.command == 'algorithms':
        algorithms = service.list_algorithms()
        if args.verbose:
            return _write_output(json.dumps([item.model_dump(mode='json', exclude_none=True) for item in algorithms], indent=2), None)
        return _write_output('\n'.join(item.id for item in algorithms), None)

    if args.command == 'hash-string':
        symbols = _expand_values(args.symbol)
        libraries = _expand_values(args.library)
        if not libraries and args.catalog:
            libraries = [catalog.library for catalog in _selected_catalogs(service, None, None, args.catalog)]
        resolved_libraries = libraries or ['']
        algorithm_params = _merge_base_values(_parse_algorithm_params(args.param), args.base)
        results = []
        for symbol in symbols:
            batch = service.hash_string_for_libraries(
                args.algorithm,
                symbol_name=symbol,
                library_names=resolved_libraries,
                xor_value=args.xor_value,
                algorithm_params=algorithm_params,
            )
            results.extend(batch.results)
        payload = {
            'algorithm_id': args.algorithm,
            'libraries': resolved_libraries,
            'symbols': symbols,
            'results': _json_ready(results),
        }
        return _write_output(json.dumps(payload, indent=2), None)

    if args.command == 'search-hash':
        catalogs = _selected_catalogs(
            service,
            args.catalog_json,
            args.input,
            args.catalog,
            show_progress=True,
            exclude_hyphenated_dlls=args.exclude_hyphenated_dlls,
            common_windows_dlls_only=args.common_windows_dlls_only,
        )
        payload = _search_hash_payload(
            service,
            args.hash_value,
            _expand_values(args.dll),
            catalogs,
            algorithm_id=args.algorithm,
            xor_value=args.xor_value,
            algorithm_params=_merge_base_values(_parse_algorithm_params(args.param), args.base),
            exclude_hyphenated_dlls=args.exclude_hyphenated_dlls,
            common_windows_dlls_only=args.common_windows_dlls_only,
        )
        return _write_output(json.dumps(payload, indent=2), None)

    if args.command == 'build-catalog':
        worker_count = _catalog_worker_count()
        progress_callback = _progress_renderer(f'Building catalogs <threads: {worker_count}>') if sys.stderr.isatty() else None
        result = service.build_catalogs_from_paths(
            [Path(item) for item in args.input],
            progress_callback=progress_callback,
            max_workers=worker_count,
        )
        return _write_output(json.dumps(result.model_dump(mode='json', exclude_none=True), indent=2), args.output)

    if args.command == 'export-enum':
        catalogs = _selected_catalogs(service, args.catalog_json, args.input, args.catalog, show_progress=True)
        dlls = _expand_values(args.dll)
        return _enum_output(
            service,
            args.algorithm,
            dlls,
            catalogs,
            args.output,
            xor_value=args.xor_value,
            algorithm_params=_merge_base_values(_parse_algorithm_params(args.param), args.base),
        )

    if args.command == 'bulk-auto':
        catalogs = _selected_catalogs(
            service,
            args.catalog_json,
            args.input,
            args.catalog,
            show_progress=True,
            exclude_hyphenated_dlls=args.exclude_hyphenated_dlls,
            common_windows_dlls_only=args.common_windows_dlls_only,
        )
        payload = service.bulk_auto_export(
            hash_value=args.hash_value,
            algorithm_id=args.algorithm,
            library_names=_expand_values(args.dll) or None,
            catalog_names=_expand_values(args.catalog) or None,
            catalogs=catalogs,
            xor_value=args.xor_value,
            algorithm_params=_merge_base_values(_parse_algorithm_params(args.param), args.base),
            exclude_hyphenated_dlls=args.exclude_hyphenated_dlls,
            common_windows_dlls_only=args.common_windows_dlls_only,
        )
        return _write_output(
            json.dumps(
                {
                    'algorithm_id': payload.algorithm_id,
                    'query_hash_input': payload.query_hash_input,
                    'query_hash_unsigned_int': payload.query_hash_unsigned_int,
                    'query_hash_hex': payload.query_hash_hex,
                    'matches': _json_ready(payload['matches']),
                    'exports': _json_ready(payload['exports']),
                },
                indent=2,
            ),
            None,
        )

    parser.error(f'Unknown command: {args.command}')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
