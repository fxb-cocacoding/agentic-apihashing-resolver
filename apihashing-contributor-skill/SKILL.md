---
name: apihashing-contributor
description: Use when adding, testing, or reloading APIHashing packs, API hash implementations, catalogs, CLI/REST/MCP workflows, or agent-driven hash resolution.
---

# APIHashing Contributor Skill

This skill explains how agents and developers add packs and API-hash implementations, then test and reload them without restarting Docker.

## 1) Add a new pack

Preferred agent workflow (recommended):

```bash
apihashing init --workspace ./apihashing-workspace --pack-name team-pack
```

This creates a standalone workspace and a new pack skeleton under `packs/team-pack`.
By default it also copies bundled reference packs for immediate local testing.

Then separate the pack repository from the core engine repository:

```bash
cd apihashing-workspace/packs/team-pack
git init
# push this pack to a dedicated repository
```

If needed, link it back into the core repository as a submodule:

```bash
git submodule add <pack-repo-url> packs/team-pack
```

Manual pack creation is still supported:

Create this minimal layout:

```text
packs/
  your-pack/
    algorithms/
      python/
      native/
    catalogs/
      pe/
      elf/
      macho/
      wordlists/
```

Notes:
- `pack.yaml` is optional.
- Discovery is convention-based:
  - Python: `packs/<pack>/algorithms/**/*.py`
  - Native C shared objects: `packs/<pack>/algorithms/native/**/*.hash.so`
  - Catalogs: `packs/<pack>/catalogs/**/*.json` and `**/*.json.xz`

## 2) Add a Python API hash implementation

Create one file under `algorithms/` (single-file design):

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
    description="Example algorithm",
    author="Your Team",
    source="https://example.local/research",
    license="Apache-2.0",
    hash_size_bits=32,
)
```

Rules:
- Put all logic and metadata in one file.
- `id` must be unique.
- If your callback accepts `params`, base values and custom knobs can be passed via API/CLI.

## 3) Add a native C API hash implementation

Place C source in `packs/<pack>/algorithms/native/` and build a `*.hash.so`.
One `.hash.so` may export one or many hash implementations (descriptor ABI).

Rebuild from backend API (no Docker command required once stack is running):

```bash
curl -sS -X POST http://localhost:8000/admin/rebuild-native \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## 4) Add or update library catalogs locally

Build catalog JSON from local DLL/SO/Mach-O files:

```bash
python -m apihashing build-catalog --input /path/to/libs --output merged.json
python -m apihashing build-catalog --input /path/to/libs --output merged.json.xz
```

Add new libraries by copying catalog files into a pack, for example:

```text
packs/your-pack/catalogs/pe/new_windows_libs.json.xz
packs/your-pack/catalogs/wordlists/new_symbols.json
```

Then reload runtime state without restart:

```bash
curl -sS -X POST http://localhost:8000/admin/reload \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## 5) Run and test via API

Useful endpoints:
- `GET /algorithms`
- `GET /catalogs`
- `POST /hash-string`
- `POST /search-hash`
- `POST /resolve`
- `POST /export-enum`
- `POST /admin/reload`
- `POST /admin/rebuild-native`

## 6) Run and test via CLI (no Docker required)

```bash
source venv/bin/activate
python -m apihashing algorithms
python -m apihashing hash-string --algorithm demo_hash --library kernel32.dll --symbol GetProcAddress
python -m apihashing search-hash --hash 0x7c0017bb --dll kernel32.dll
python -m apihashing export-enum --algorithm demo_hash --dll kernel32.dll --output demo.h
```

## 7) Binary API-hash resolution workflow

When reversing inlined API resolution from a sample:

1. Start from `entry` and follow callees until you hit resolver-style loops.
2. Search decompiled source and assembly operations for PEB/TEB walking patterns: x86 `fs:[0x18]` for TEB self and `fs:[0x30]` for PEB; x64 `gs:[0x30]` for TEB self and `gs:[0x60]` for PEB; loader traversal through x86 `PEB+0x0C`/`Ldr+0x14` or x64 `PEB+0x18`/`Ldr+0x20`; export-directory walking; or module-name checks/hashes for `ntdll.dll`, `kernel32.dll`, and `kernelbase.dll`.
3. From that discovery point, look for a function called inside a loop to obtain or transform a value that is later compared against an immediate constant. That compare constant is usually the target API hash.
4. Search hash packs for constants from the candidate function. Known constants often mean the hash function is already implemented:
   - `rg -n "0x1000193|16777619" packs apihashing/bundled_packs`
5. Validate broad first across loaded DLL catalogs and exports, then narrow:
   - `python -m apihashing search-hash --hash 0x... --algorithm <candidate>`
   - `python -m apihashing search-hash --hash 0x... --algorithm <candidate> --dll kernel32.dll --dll ntdll.dll`
6. If no result appears, search outward for API resolution of `GetProcAddress` and `LoadLibraryA`/`LoadLibraryW`, including the case where they are hashed imports resolved after `kernel32.dll` or `ntdll.dll` handles were obtained by PEB/TEB walking.

## 8) MCP server for agent workflows

Run MCP bridge to expose APIHashing to Codex/Claude/Gemini style tools:

```bash
APIHASHING_MCP_API_URL=http://localhost:8000 python -m apihashing.mcp_server
```

Available MCP tools include packs, algorithms, catalogs, hash/search/resolve/export, and admin reload/rebuild operations.

## 9) Runtime behavior in Docker Compose

After containers are running:
- Python algorithm edits: call `/admin/reload`
- Native C edits: call `/admin/rebuild-native`

Do not require `docker restart` or `docker compose up --build` for normal algorithm/catalog iteration.

## 10) Permission rule for agents

If MCP is unavailable and an agent needs to execute arbitrary Python code directly, the agent should ask the user for explicit approval before running that Python execution.
