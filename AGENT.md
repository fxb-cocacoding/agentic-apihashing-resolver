# AGENT.md

This repository is intended to be used by AI tools and reverse-engineering workflows.

The main goal is:
- detect API hashing in malware
- derive the hashing algorithm from disassembly or decompiler output
- implement that algorithm as a local plugin
- use this tool to resolve hashed Windows API imports back to concrete DLL and function names

Typical upstream tools are:
- IDA Pro via MCP or plugin tooling
- Ghidra via MCP or scripting
- Binary Ninja via MCP or scripting
- rizin / radare2 workflows

## Core idea

When an AI tool sees code that hashes API names instead of importing them directly, it should:
1. identify the exact hash algorithm behavior from code
2. create one new algorithm file
3. run this project against Windows export catalogs
4. return the resolved API candidates to the RE tool

This repository is not primarily for manually curated hash implementations. 
It is designed so AI tools can add new ones quickly and safely.
Create sub-repositories or packs in `packs/<your-pack>`.

## Non-negotiable authoring rules

1. One Python hash implementation must live in one file.
2. Users and AI tools should not need to edit more than that one file for a new Python hash.
3. Do not add shared helper backends for Python hash plugins.
4. Keep imported or reconstructed code close to the original malware logic.
5. Use `byteops` library for arithmetic and logical operations, specially where register-width behavior is unclear without it.
6. Do not introduce generic reflective width frameworks.
7. Prefer explicit helpers like `ror`, `rol`, `shl32`, `shr32`, `not16` when needed.

Note that you can also write and compile api hash implementations in C.

## Where to add a new hash

When starting a api hash deobfuscation session or resuming one, ask for user which pack to use.
List `packs/` and ask which one to use for adding new hashes, or ask the user if he wants a new pack.
If the user wants a new pack, create the folder accoringly. Also suggest the use of git for the pack to integrate it as submodule.
Add one file under:

```text
packs/<your-pack>/algorithms/
```

Examples:

```text
packs/private-team-pack/algorithms/my_family_crc32.py
packs/private-team-pack/algorithms/weird_loader_xor.py
```

The runtime discovers Python algorithms automatically.
No YAML registration is required.

## Preferred plugin shape

Use `FunctionHashImplementation`.
Only `id` and `callback` are required.

Two callback shapes are supported:

1. Simple form:
```python
def _hash(library_name: str, symbol_name: str) -> int:
    ...
```

2. Parameterized form:
```python
def _hash(library_name: str, symbol_name: str, params: dict[str, object]) -> int:
    ...
```

Use the 3-argument form when the malware varies a seed, base, xor constant, or another per-call modifier.

Minimal example:

```python
import zlib

from apihashing.plugin_api import FunctionHashImplementation


def _hash(library_name: str, symbol_name: str, params: dict[str, object]) -> int:
    base = int(params.get("base", 0))
    data = f"{library_name}{symbol_name}".encode("utf-8")
    return (zlib.crc32(data) + base) & 0xFFFFFFFF


HASH_IMPLEMENTATION = FunctionHashImplementation(
    id="custom_crc32_base",
    callback=_hash,
    hash_size_bits=32,
    description="CRC32 over DLL+function with per-call base value.",
)
```

## When to use algorithm params

Use `params` when the algorithm stays the same but malware changes values per call, for example:
- per-import base value
- per-function xor value
- seed that differs by sample or import site
- case mode chosen at runtime
- DLL prefix/suffix handling controlled by flags

Current surfaces already support passing these values:
- REST: `algorithm_params`
- CLI: repeated `--param key=value`
- Web UI: `Algorithm Params` JSON field

Example CLI:

```bash
python -m apihashing hash-string \
  --algorithm custom_crc32_base \
  --library kernel32.dll \
  --symbol CreateFileW \
  --param base=0x1000
```

Example REST body:

```json
{
  "algorithm_id": "custom_crc32_base",
  "library_name": "kernel32.dll",
  "symbol_name": "CreateFileW",
  "algorithm_params": {
    "base": "0x1000"
  }
}
```

## What an AI tool should extract from IDA/Ghidra

When reconstructing an API hash, collect these facts from the malware code:
- which string is hashed:
  - function only
  - dll + function
  - uppercase dll + function
  - utf-16 dll + ascii function
  - null-terminated or not
- exact initial state:
  - seed
  - base
  - accumulator init
- exact transforms:
  - rotate count and direction
  - shift pattern
  - add/sub/xor/multiply constants
  - case normalization
  - trimming of `Nt` / `Zw`
  - ordinal-specific handling
- output width:
  - 16-bit
  - 32-bit
  - 64-bit
  - larger
- any per-import or per-function modifiers

Do not approximate these details. Small deviations produce false positives or no matches.

## AI workflow for MCP-based RE integrations

Recommended workflow for an MCP-enabled IDA Pro or Ghidra agent:

1. Inspect the suspicious function.
2. Identify whether it hashes API names, module names, or both.
3. Recover the exact algorithm behavior from disassembly/decompiler output.
4. Create one new plugin file in a private or local pack.
5. If needed, include a 3-argument callback and accept `params` such as `base` or `xor`.
6. Run the CLI or REST API against known Windows export catalogs.
7. Return candidate matches to the RE tool.
8. Rename variables or annotate the call sites in the RE database.

This means the RE tool should treat this repository as the execution backend for resolution, not as the source of truth for disassembly.

## Expected AI behavior

AI tools working in this repository should:
- preserve the one-file rule
- preserve upstream attribution and licenses when adapting public algorithms
- prefer exact reconstruction over abstraction
- avoid editing unrelated files when adding one algorithm
- use existing catalogs or build them from DLLs/shared objects locally
- validate results against known imports before claiming success

AI tools should not:
- invent helper frameworks for a single hash
- spread one algorithm over multiple Python files
- convert original code into a style that obscures the logic
- assume file format restrictions like PE vs ELF change the hash itself

## Validation expectations

After adding a new algorithm, verify at least one of:
- `python -m apihashing hash-string ...`
- `python -m apihashing search-hash ...`
- `python -m pytest tests -q`

If the algorithm comes from observed malware, validate it against at least one known hash/import pair from the sample.

## Windows API resolution focus

This project is primarily aimed at resolving Windows API hashing.
That means the common end result should be:
- hashed value observed in malware
- resolved to `dll!function`
- returned to the RE tool for annotation

Typical examples:
- `kernel32.dll!CreateFileW`
- `kernel32.dll!GetProcAddress`
- `ntdll.dll!NtAllocateVirtualMemory`
- `advapi32.dll!RegOpenKeyExW`

## Current package/runtime names

The product name may evolve, but today the code/package entrypoints are still:
- Python package: `apihashing`
- CLI: `python -m apihashing`

Use the current runtime names unless the repository explicitly renames them later.
