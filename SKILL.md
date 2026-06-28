# APIHashing Usage And Plugin Authoring Skill

This skill is for using APIHashing as an analysis backend and adding new hash plugins in packs.
It is not about contributing to framework internals.

## 1) Start the backend

Run locally:

```bash
python3 -m venv venv
. venv/bin/activate
python -m pip install -e .
uvicorn apihashing.app:create_app --factory --reload
```

Backend base URL: `http://localhost:8000`

## 2) Use the Python CLI

Use either `apihashing ...` or `python -m apihashing ...`.

Core commands:

```bash
python -m apihashing algorithms
python -m apihashing hash-string --algorithm payouts_king_crc32 --library kernel32.dll --symbol GetProcAddress
python -m apihashing search-hash --hash 0x7c0017bb --dll kernel32.dll
venv/bin/python3 -m apihashing.cli search-hash --hash 0x234C1F67 --algorithm d68_fnv1a --base 0x8E8A2795
python -m apihashing export-enum --algorithm payouts_king_crc32 --dll kernel32.dll --output kernel32_enum.h
python -m apihashing build-catalog --input /path/to/libs --output merged.json.xz
python -m apihashing bulk-auto --algorithm payouts_king_crc32 --hash 0x7c0017bb --dll kernel32.dll
```

Notes:
- `--param key=value` passes algorithm-specific options.
- `--base` and `--xor` are supported on hashing/search/export flows.
- `--project-root` or `APIHASHING_PROJECT_ROOT` can point to a different packs root.

## 3) Use the REST API

Useful read endpoints:
- `GET /health`
- `GET /packs`
- `GET /algorithms`
- `GET /catalogs`

Core POST endpoints:
- `POST /hash-string`
- `POST /search-hash`
- `POST /resolve`
- `POST /export-enum`
- `POST /bulk-auto`
- `POST /build-catalogs`

Admin endpoints for live iteration:
- `POST /admin/reload`
- `POST /admin/rebuild-native`

Examples:

```bash
curl -sS http://localhost:8000/algorithms

curl -sS -X POST http://localhost:8000/hash-string \
  -H 'Content-Type: application/json' \
  -d '{
    "algorithm_id":"payouts_king_crc32",
    "library_name":"kernel32.dll",
    "symbol_name":"GetProcAddress"
  }'

curl -sS -X POST http://localhost:8000/search-hash \
  -H 'Content-Type: application/json' \
  -d '{
    "hash_value":"0x7c0017bb",
    "library_names":["kernel32.dll"]
  }'
```

## 4) Use the MCP server

Run the bridge:

```bash
APIHASHING_MCP_API_URL=http://localhost:8000 python -m apihashing.mcp_server
```

Main MCP tool groups:
- connectivity: `bridge_ping`, `backend_health`
- inventory: `packs_list`, `algorithms_list`, `catalogs_list`
- hash workflows: `hash_string`, `search_hash`, `resolve_hash`, `export_enum`, `bulk_auto`
- admin: `admin_reload`, `admin_rebuild_native`
- authoring helpers: `validate_pack`, `scaffold_algorithm`, `cli_init_workspace`, `cli_build_catalog`

Tool argument patterns are documented in `docs/mcp-examples.md`.

## 5) Binary API-hash resolution workflow (essential)

Use this workflow when reversing inlined API resolution from a sample.

1. Start from `entry` and follow callees until you hit resolver-style loops.
2. Search decompiled source and assembly operations for PEB/TEB walking patterns:
   - `fs`/`gs` segment-register access, PEB loader-list traversal, or export-directory walking
   - x86 markers: `fs:[0x18]` for TEB self, `fs:[0x30]` for PEB, `PEB+0x0C` for `Ldr`, `Ldr+0x14` for `InMemoryOrderModuleList`
   - x64 markers: `gs:[0x30]` for TEB self, `gs:[0x60]` for PEB, `PEB+0x18` for `Ldr`, `Ldr+0x20` for `InMemoryOrderModuleList`
   - module-name checks or hashes for `ntdll.dll`, `kernel32.dll`, or `kernelbase.dll`
   - direct imports or hashed resolution of `GetProcAddress` and `LoadLibraryA`/`LoadLibraryW`
3. From that discovery point, look for a function called inside a loop to obtain or transform a value that is later compared against an immediate constant. That compare constant is usually the target API hash.
4. Search for FNV-1a multiply constant `0x1000193` and other distinctive constants from the candidate hash function to find good candidates.
5. Search the hash packs for constants from the candidate function. If a constant is already known in a pack, the hash function may already be implemented:
   - `rg -n "0x1000193|16777619" packs apihashing/bundled_packs`
6. In the candidate function, extract one pair:
   - base seed from `MOV <reg>, 0x...` before hash loop
   - compare hash from `CMP <reg>, 0x...` after loop
7. Validate immediately with APIHashing CLI before continuing with more pairs. Start broad across all loaded DLL catalogs and their exports, then narrow to likely modules when needed:
   - `python -m apihashing search-hash --hash 0x... --algorithm <candidate>`
   - `python -m apihashing search-hash --hash 0x... --algorithm <candidate> --dll kernel32.dll --dll ntdll.dll`
8. If no result appears, search outward from the resolver: locate how `GetProcAddress`/`LoadLibraryA`/`LoadLibraryW` are resolved, including the case where their own hashes are compared first after handles to `kernel32.dll` or `ntdll.dll` were obtained by PEB/TEB walking.

Fast validation examples:

```bash
# base-dependent case (harder, common in custom malware hashers)
venv/bin/python3 -m apihashing.cli search-hash --hash 0x55832F0B --algorithm d68_fnv1a --base 0xC60BA40C

# easier case (no custom base required)
python -m apihashing search-hash --hash 0x7c0017bb --algorithm fnv1a
```

If no result:
- retry with the exact observed base value
- try alternate candidate algorithms (`d*`, `fnv*`, `ror*`, `crc*`)
- verify operand width/normalization (32-bit wrap, xor preprocessing)

## 6) Add a new plugin pack

Preferred pack setup:

```bash
python -m apihashing init --workspace ./apihashing-workspace --pack-name team-pack
```

This creates `apihashing-workspace/packs/team-pack` plus pack skeleton directories.

Discovery conventions:
- Python plugins: `packs/<pack>/algorithms/**/*.py`
- Native plugins: `packs/<pack>/algorithms/native/**/*.hash.so`
- Catalogs: `packs/<pack>/catalogs/**/*.json` and `*.json.xz`
- `pack.yaml` is optional

## 7) Add a Python hash plugin

Create one file in `packs/<pack>/algorithms/`:

```python
from apihashing.plugin_api import FunctionHashImplementation, HashValue


def _hash(library_name: str, symbol_name: str, params: dict[str, object]) -> HashValue:
    base = int(params.get("base", 0))
    value = (sum(symbol_name.encode("utf-8")) + base) & 0xFFFFFFFF
    return HashValue.from_int(value, bit_length=32)


HASH_IMPLEMENTATION = FunctionHashImplementation(
    id="demo_hash",
    callback=_hash,
    display_name="Demo Hash",
    description="Example symbol hash with optional base",
    author="Your Team",
    hash_size_bits=32,
)
```

Rules:
- one algorithm per file
- keep logic and metadata together
- keep ids unique

## 8) Add a native plugin

Place native source/build files under `packs/<pack>/algorithms/native/`, build `*.hash.so`, then rebuild runtime:

```bash
curl -sS -X POST http://localhost:8000/admin/rebuild-native \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## 9) Add or update catalogs

Build local catalogs:

```bash
python -m apihashing build-catalog --input /path/to/libs --output merged.json.xz
```

Copy catalog files into a pack, then reload:

```bash
curl -sS -X POST http://localhost:8000/admin/reload \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## 10) Verify plugin behavior

After adding or editing plugins:
- run CLI checks (`algorithms`, `hash-string`, `search-hash`)
- optionally run tests: `python -m pytest tests -q`
- for runtime sessions, use `/admin/reload` for Python/catalog changes and `/admin/rebuild-native` for native changes

## 11) Agent safety

If MCP is unavailable and an agent must execute arbitrary Python directly, it should request explicit user approval first.
