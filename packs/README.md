# Pack Repositories

Each directory under `packs/` is treated as an installable pack when it contains `algorithms/` or `catalogs/`.

Recommended layout for external repositories:

```bash
apihashing init --workspace ./apihashing-workspace --pack-name team-pack
cd apihashing-workspace/packs/team-pack
git init
# push pack repository
```

Then connect to the core engine repository:

```bash
git submodule add <your-pack-repo-url> packs/<pack-name>
```

## Python packs

A Python pack repository contains:
- `catalogs/` JSON symbol catalogs
- `algorithms/*.py` or `algorithms/**/*.py` plugin files
- optional `tests/` vector fixtures

## Native packs

A native pack repository contains:
- `catalogs/` JSON symbol catalogs
- `algorithms/native/*.hash.so` shared objects
- optional `.hash.c` or build sources used to produce those shared objects
- optional `algorithms/native/Makefile` for reproducible builds

## Optional metadata

`pack.yaml` is now optional and not required for runtime discovery.
If present, it is only treated as pack-level metadata such as `name` or `version`.

## Authoring rule

The intended author workflow is one file per hash.

- Add one Python file under `algorithms/`
- Either:
  - export `HASH_IMPLEMENTATION`
  - or provide a HashDB-style `hash(data)` function and optional metadata constants
- Do not edit a central registry
- Do not edit YAML for runtime discovery
- For scaffolded templates, source files come from `apihashing/templates/algorithms/{python,c}`.
- Author is per hash implementation, not pack-level metadata.


- The default pack ships:
  - `payouts_king_crc32` (Python demo)
  - `internal_djb2_symbol_c` (native C demo)
  - Payouts King wordlists
- Imported OALabs HashDB algorithms that trace back to FLARE shellcode are marked with `copied_from_flare_shellcode` in API results and shown in the UI as `flare shellcode lineage`.
