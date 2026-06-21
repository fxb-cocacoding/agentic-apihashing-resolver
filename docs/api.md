# REST API

## Endpoints
- `GET /health`
- `POST /admin/reload`
- `POST /admin/rebuild-native`
- `GET /packs`
- `POST /packs/{pack_name}`
- `GET /algorithms`
- `GET /catalogs`
- `GET /hash`
- `GET /hash/{algorithm_id}/{hash_value}`
- `GET /module/{module_name}/{algorithm_id}/`
- `GET /module/{module_name}/{algorithm_id}/{permutation}`
- `POST /hunt`
- `POST /resolve`
- `POST /search-hash`
- `POST /hash-string`
- `POST /build-catalogs`
- `POST /export-enum`
- `POST /bulk-auto`
- `POST /analyze-binary`
- `POST /validate-pack`
- `POST /scaffold/algorithm`

## Algorithm discovery
- Python plugins are auto-discovered from `packs/<pack>/algorithms/**/*.py`
- Native plugins are auto-discovered from `packs/<pack>/algorithms/native/**/*.hash.so`
- `/algorithms` returns the loaded algorithm id, display name, bit width, source, implementation type, and module path
- Python discovery supports:
  - project-native files exporting `HASH_IMPLEMENTATION` or `HASH_IMPLEMENTATIONS`
  - HashDB-style one-file modules exporting `hash(data)` with optional `DESCRIPTION`, `TYPE`, `SOURCE`, and `LICENSE`
- The default compose backend command builds native plugins first via: `make -C packs/default-pack/algorithms/native all`
- Runtime reload endpoints:
  - `POST /admin/reload` rescans packs/catalogs/algorithms without restart
  - `POST /admin/rebuild-native` runs `make` for native plugin directories and then reloads runtime state

## Catalog sources
- `GET /catalogs` returns the active catalogs already loaded from packs
- `GET /catalogs` supports backend-side `filter_text`, `sort_by`, `sort_direction`, `exclude_hyphenated_dlls`, and `common_windows_dlls_only`
- `/build-catalogs` accepts multiple uploaded library binaries and returns merged transient catalogs
- The uploaded filename is used as the library name and exported symbols are extracted with `LIEF`
- Library catalog JSON omits `kind`; only wordlists emit `kind: "wordlist"`
- The backend remains stateless: transient catalogs can be supplied again on later requests instead of being stored server-side

## Hash lookups
- `/resolve` checks one requested algorithm against the active loaded catalogs
- `/search-hash` checks one requested hash value across algorithms and catalogs
- `/search-hash` uses multiprocessing by default when eligible; disable with `APIHASHING_ENABLE_MP_SEARCH=0`
- process-pool worker cap is configurable with `APIHASHING_MP_SEARCH_MAX_WORKERS` (default: CPU count)
- `/search-hash` accepts:
  - `hash_value`
  - optional `library_name` substring filter
  - optional `library_names` exact multi-library filter
  - optional `catalog_names` exact catalog filter
  - optional `catalogs` array for transient browser/CLI catalogs
  - optional `xor_value`
- In the browser, extra libraries are normally attached per request and converted to transient catalogs before the search request is sent
- When transient catalogs are supplied, they are merged with active catalogs for the search
- `/hash-string` hashes a provided string for one requested algorithm, with optional `library_name`, `library_names`, and `xor_value`

## HashDB compatibility
- `GET /hash` returns HashDB-style algorithm metadata:
  - `algorithm`
  - `type`
- `GET /hash/{algorithm_id}/{hash_value}` returns:
  - `{"hashes": [{"hash": ..., "string": {...}}]}`
- `GET /module/{module_name}/{algorithm_id}/{permutation}` returns all hashes for one library in the same HashDB-compatible shape
- `POST /hunt` accepts `{"hashes": [...]}` and returns `{"hits": [{"algorithm": "..."}]}`
- XOR applies to `/hash` and `/hunt` lookups; `/module` responses are always raw for hashdb-ida compatibility (the client applies XOR locally when enabled)

## Enum export
- `/export-enum` renders C header enums for one or more selected libraries
- `/export-enum` accepts optional `library_names`, `catalog_names`, and transient `catalogs` that are merged with active catalogs before lookup
- In the browser, extra libraries are normally attached per request and converted to transient catalogs before the export request is sent
- `/export-enum` accepts optional `xor_value`
- `/bulk-auto` resolves one observed hash for one algorithm, groups matches by library, and returns rendered enums for each matched library

## Resolve input/output
- `/resolve` and `/search-hash` accept decimal strings, `0x` hex strings, IDA-style `...h` hex strings, or integers for `hash_value`
- Match objects include `hash_value_unsigned_int`, `hash_value_hex`, and `hash_size_bits`

## Local CLI
- `apihashing init --workspace <path> --pack-name <name> [--no-bundled-packs]`
- `apihashing algorithms`
- `apihashing hash-string --algorithm <id> --symbol <name> [--library <dll>] [--xor <value>]`
- `apihashing search-hash --hash <value> [--dll <name>] [--catalog <name>] [--catalog-json merged.json] [--input <path>] [--xor <value>]`
- `apihashing build-catalog --input <file-or-dir>... [--output merged.json.xz]`
- `apihashing export-enum --algorithm <id> --dll <name> [--catalog <name>] [--catalog-json merged.json.xz] [--input <path>] [--output header.h] [--xor <value>]`
- `apihashing bulk-auto --algorithm <id> --hash <value> [--dll <name>] [--catalog <name>] [--catalog-json merged.json.xz]`
- `--input` accepts local PE, ELF, and Mach-O library files or directories containing them
- `--output` writes xz-compressed JSON directly when the filename ends with `.json.xz`
- `build-catalog` omits libraries with zero exported symbols
- `init` creates a standalone `packs/` workspace plus one new pack skeleton and prints git/submodule separation hints

## Local catalog add/update flow
- Build local catalog from libraries:
  - `apihashing build-catalog --input /path/to/libraries --output merged.json.xz`
- Add library catalogs by copying JSON/JSON.XZ files into any pack `catalogs/` directory
- Reload runtime immediately (no Docker restart):
  - `curl -sS -X POST http://localhost:8000/admin/reload -H 'Content-Type: application/json' -d '{}'`
- Rebuild native algorithms immediately (no Docker restart):
  - `curl -sS -X POST http://localhost:8000/admin/rebuild-native -H 'Content-Type: application/json' -d '{}'`

## MCP bridge
- Start stdio MCP server:
  - `APIHASHING_MCP_API_URL=http://localhost:8000 python -m apihashing.mcp_server`
- MCP tools are wrappers around API routes and include:
  - pack/algorithm/catalog listing and pack activation
  - hash/search/resolve/hash-string/export/bulk-auto operations
  - `admin_reload` and `admin_rebuild_native`
  - file-path helpers for `/analyze-binary` and `/build-catalogs`

## Bundled hash sets
- `packs/default-pack` contains:
  - `payouts_king_crc32` (Python)
  - `internal_djb2_symbol_c` (native C)
  - bundled `system32.json.xz` Windows library catalogue
  - one merged Payouts King wordlist sourced from the Zscaler research post
- `packs/oalabs-hashdb` contains imported one-file algorithms from `OALabs/hashdb`, under Apache-2.0
- Imported OALabs HashDB algorithms that trace back to FLARE shellcode are marked with `copied_from_flare_shellcode` in API results and shown in the UI as `flare shellcode lineage`.
