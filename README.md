# APIHashing

APIHashing is a local backend for resolving API hashes during reverse engineering. It is built for agentic workflows where a coding or RE agent inspects a binary, reconstructs the API hashing algorithm, adds that algorithm as a plugin, and asks this tool to resolve hashes back to concrete exports such as `kernel32.dll!GetProcAddress`.

This repository provides:

- a Python CLI
- a FastAPI REST backend
- a stdio MCP bridge for agent tools
- a browser UI for local exploration
- convention-based Python and native hash plugin packs
- bundled reference packs, including FLARE-derived hashes and imported OALabs HashDB algorithms

## Why This Exists

LLMs often hallucinate plausible Windows API imports when malware uses API hashing. APIHashing gives the agent a deterministic tool call instead: implement or select the exact hash algorithm, run it against export catalogs, and return real candidates.

For API hash implementations that mirror assembly, use `byteops`. ByteOps provides explicit arithmetic, logical, rotate, shift, and width behavior, which prevents hallucinations around assembly operations and CPU register semantics. Prefer concrete helpers such as `ror_dword`, `rol_dword`, `shl_dword`, and `shr_dword` instead of asking an agent to invent Python equivalents for machine instructions.

## Quick Start

Run the development stack with Docker:

```bash
docker compose up --build
```

Then open:

- Backend: `http://localhost:8000`
- UI: `http://localhost:5173`

Or run the backend locally:

```bash
python3 -m venv venv
. venv/bin/activate
python -m pip install -e .
uvicorn apihashing.app:create_app --factory --reload
```

The CLI works without Docker:

```bash
apihashing algorithms
apihashing hash-string --algorithm payouts_king_crc32 --library kernel32.dll --symbol GetProcAddress
apihashing search-hash --hash 0x7c0017bb --dll kernel32.dll
```

## Install The Agent Skill

The installable skill is in:

```text
apihashing-contributor-skill/SKILL.md
```

Install the whole folder, not just the Markdown file, so future references or helper files can live beside `SKILL.md`.

### Claude

For Claude Code, install it as a local user skill:

```bash
mkdir -p ~/.claude/skills
cp -R apihashing-contributor-skill ~/.claude/skills/apihashing-contributor
```

Start a new Claude Code session after installing. If you use Claude.ai Skills instead of Claude Code, zip the `apihashing-contributor-skill` folder and upload it through the Claude Skills settings. Keep `SKILL.md` at the root of the uploaded folder.

### Codex

For a repository-scoped Codex skill, install it under `.agents/skills`:

```bash
mkdir -p .agents/skills
cp -R apihashing-contributor-skill .agents/skills/apihashing-contributor
```

For a personal Codex skill available across repositories, install it under your home directory:

```bash
mkdir -p ~/.agents/skills
cp -R apihashing-contributor-skill ~/.agents/skills/apihashing-contributor
```

Codex detects skill changes automatically in many cases. If the skill does not appear, restart Codex or start a new thread. You can then ask Codex to use the skill explicitly with:

```text
$apihashing-contributor
```

## Common Workflows

### Resolve One Hash

```bash
apihashing search-hash \
  --hash 0x7c0017bb \
  --dll kernel32.dll
```

With an algorithm parameter:

```bash
apihashing search-hash \
  --hash 0x234C1F67 \
  --algorithm d68_fnv1a \
  --base 0x8E8A2795
```

### Hash One Export

```bash
apihashing hash-string \
  --algorithm payouts_king_crc32 \
  --library kernel32.dll \
  --symbol GetProcAddress
```

With an XOR modifier:

```bash
apihashing hash-string \
  --algorithm payouts_king_crc32 \
  --library kernel32.dll \
  --symbol CreateFileW \
  --xor 0x13579BDF
```

### Export An Enum Header

```bash
apihashing export-enum \
  --algorithm payouts_king_crc32 \
  --dll kernel32.dll \
  --dll user32.dll \
  --output headers/
```

### Build A Local Catalog

```bash
apihashing build-catalog \
  --input /path/to/System32 \
  --output system32.json.xz
```

By default, the CLI expects to run from the project root so it can find `packs/`. If needed, set `APIHASHING_PROJECT_ROOT` or pass `--project-root`.

When installed via `pipx` or `uv tool`, bundled packs are used automatically if no local `packs/` directory is present.

## MCP Bridge

Run the stdio MCP server for Codex, Claude, Gemini, or another MCP-capable tool:

```bash
APIHASHING_MCP_API_URL=http://localhost:8000 python -m apihashing.mcp_server
```

The MCP server wraps the API endpoints for:

- pack, catalog, and algorithm listing
- hash, search, resolve, and enum export actions
- admin reload and native rebuild actions
- pack and algorithm scaffolding helpers

Tool argument examples are in [docs/mcp-examples.md](docs/mcp-examples.md).

## Web UI

Run the UI locally:

```bash
npm --prefix ui install
npm --prefix ui run dev
```

The UI has tabs for:

- `Hashes`
- `Export Enum`
- `Packs`
- `Docs`

The browser UI uses shipped catalogs by default. For extra libraries, attach files directly in the `Search Hash` or `Export Enum` form for that request.

## Docker Compose Development

The compose file is a hot-reload development stack for local or submodule-based API hashing method packs.

On Linux, export your host UID and GID before starting the stack so bind-mounted files stay owned by your user:

```bash
export UID=$(id -u)
export GID=$(id -g)
docker compose up --build
```

If `UID` and `GID` are not set, compose falls back to `1000:1000`.

If an older compose setup installed dependencies as root, reset stale volumes once:

```bash
docker compose down -v
docker compose up --build
```

Runtime development endpoints:

- `POST /admin/reload` after Python algorithm or catalog changes
- `POST /admin/rebuild-native` after C/native changes

Docker details:

- Backend startup runs `make -C packs/default-pack/algorithms/native all` before launching uvicorn.
- Python reload uses polling through `WATCHFILES_FORCE_POLLING=true`.
- Vite reload uses polling.
- `APIHASHING_SEARCH_MAX_WORKERS` limits workers for `/search-hash`.
- `APIHASHING_EXPORT_MAX_WORKERS` limits workers for multi-library enum export.
- `APIHASHING_ENABLE_MP_SEARCH` defaults to enabled with `1`.
- `APIHASHING_MP_SEARCH_MAX_WORKERS` caps process-pool workers for `/search-hash`.

If you change `vite.config.js`, Dockerfiles, or dependency metadata, rebuild the affected service:

```bash
docker compose up --build -d backend ui
```

## Pack Layout

Python hash plugins are discovered from:

```text
packs/<pack>/algorithms/**/*.py
```

Native hash plugins are discovered from:

```text
packs/<pack>/algorithms/native/**/*.hash.so
```

Catalog files are discovered from:

```text
packs/<pack>/catalogs/**/*.json
packs/<pack>/catalogs/**/*.json.xz
```

`pack.yaml` is optional. Discovery is convention-based.

A minimal Python pack:

```text
packs/
  my-pack/
    catalogs/
      pe/
        kernel32.json
    algorithms/
      my_hash.py
```

A minimal native pack:

```text
packs/
  native-pack/
    catalogs/
      pe/
        demo.json
    algorithms/
      native/
        Makefile
        native_bundle.hash.so
```

## Initialize An External Pack Workspace

Use `init` to create a separate workspace and a new pack skeleton for agent-driven hash authoring:

```bash
apihashing init --workspace ./apihashing-workspace --pack-name team-pack
```

This creates:

- `apihashing-workspace/packs/team-pack`
- bundled reference packs, unless `--no-bundled-packs` is used

Recommended separation workflow:

```bash
cd apihashing-workspace/packs/team-pack
git init
# push this pack to its own repository
```

Then link it back into the core repository if desired:

```bash
git submodule add <pack-repo-url> packs/team-pack
```

## Python Plugin Shape

The simplest authoring path is one file in `algorithms/`. You can export `HASH_IMPLEMENTATION` directly or drop in a HashDB-style file with a `hash(data)` function.

Project-native example:

```python
from byteops import ByteOps

from apihashing.plugin_api import FunctionHashImplementation, HashValue


OPS = ByteOps()


def _hash(library_name: str, symbol_name: str, params: dict[str, object]) -> HashValue:
    seed = int(params.get("seed", 0))
    value = seed
    for byte in symbol_name.encode("ascii"):
        raw = (value & 0xFFFFFFFF).to_bytes(4, "little")
        value = int.from_bytes(OPS.ror_dword(raw, 13), "little")
        value = (value + byte) & 0xFFFFFFFF
    return HashValue.from_int(value, bit_length=32)


HASH_IMPLEMENTATION = FunctionHashImplementation(
    id="demo_ror13_add",
    callback=_hash,
    display_name="Demo ROR13 Add",
    description="Example API hash using ByteOps for assembly-like 32-bit behavior.",
    author="Your Team Name",
    hash_size_bits=32,
)
```

Rules:

- Keep one Python hash implementation in one file.
- Keep logic and metadata together.
- Keep IDs unique.
- Use the 3-argument callback when the malware varies a seed, base, XOR constant, case mode, or other per-call modifier.
- Use ByteOps for assembly-style arithmetic, rotates, shifts, masks, and width-specific behavior.

HashDB-style example:

```python
DESCRIPTION = "Simple symbol-only hash"
TYPE = "unsigned_int"
TEST_1 = 0x12345678

SOURCE = "https://example.test/demo_hash.py"
LICENSE = "Apache-2.0"

def hash(data):
    return 0x12345678
```

Only the algorithm file needs to be added. No YAML edit is required.

## Native Plugin Shape

Each discovered `.hash.so` exports a descriptor-based ABI:

- `uint32_t apihash_plugin_count(void)`
- `const apihash_descriptor* apihash_plugin_descriptor(uint32_t index)`
- one exported compute function per descriptor named by `symbol_name`

This allows one shared object to expose one or many hash implementations.

Author attribution is implementation-level:

- Python: set `author=` in `FunctionHashImplementation`, or `AUTHOR` in HashDB-style modules.
- Native C: optionally export `const char* apihash_plugin_author(uint32_t index)`.

Build native plugins locally:

```bash
make -C packs/default-pack/algorithms/native all
```

Or trigger rebuild and reload through the running backend:

```bash
curl -sS -X POST http://localhost:8000/admin/rebuild-native \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## REST API

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

Admin endpoints:

- `POST /admin/reload`
- `POST /admin/rebuild-native`

Example:

```bash
curl -sS -X POST http://localhost:8000/hash-string \
  -H 'Content-Type: application/json' \
  -d '{
    "algorithm_id": "payouts_king_crc32",
    "library_name": "kernel32.dll",
    "symbol_name": "GetProcAddress"
  }'
```

## Current Capabilities

- REST API, web UI, local CLI, and MCP bridge share the same backend service layer.
- Hash results carry both hex and unsigned integer representations.
- Project-native plugins and HashDB-style one-file modules are supported.
- HashDB-compatible routes are exposed for drop-in IDA plugin use: `GET /hash`, `GET /hash/{algorithm}/{value}`, `GET /module/{module}/{algorithm}/{permutation}`, and `POST /hunt`.
- Optional XOR modifiers are supported in REST and CLI flows.
- Runtime reload endpoints allow zero-restart development.
- Bundled reference packs are shipped inside the Python package for standalone `pipx` and `uv` usage.

## Notes

- `packs/default-pack` no longer contains `pack.yaml`; it was only a leftover from the legacy manifest-based loader.
- The default pack ships `payouts_king_crc32`, `internal_djb2_symbol_c`, a compressed `system32.json.xz` Windows library catalog, and one merged Payouts King wordlist sourced from the Zscaler research post.
- `packs/oalabs-hashdb` contains imported one-file algorithms from `OALabs/hashdb` with per-file source and Apache-2.0 license metadata.
- Imported OALabs HashDB algorithms that trace back to FLARE shellcode are marked with `copied_from_flare_shellcode` in API results and shown in the UI as `flare shellcode lineage`.
- Scaffolding templates are file-based under `apihashing/templates/algorithms/{python,c}` and are consumed by `POST /scaffold/algorithm`.

More details:

- [docs/api.md](docs/api.md)
- [docs/mcp-examples.md](docs/mcp-examples.md)
- [packs/README.md](packs/README.md)
- [AGENT.md](AGENT.md)
- [SKILL.md](SKILL.md)
