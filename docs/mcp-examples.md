# MCP Tool Examples

This file shows example `arguments` payloads for each `apihashing-mcp` tool.

Notes:
- Fields like `library_names`, `catalog_names`, and `pack_names` are comma-separated strings (for example, `"kernel32.dll,user32.dll"`).
- `algorithm_params_json` is a JSON object encoded as a string (for example, `"{\"base_values\":[\"0x10\",\"0x20\"]}"`).

## Connectivity

`bridge_ping`
```json
{}
```

`backend_health`
```json
{}
```

## Runtime Admin

`admin_reload`
```json
{}
```

`admin_rebuild_native`
```json
{
  "pack_names": "default-pack,oalabs-hashdb",
  "target": "all"
}
```

## Packs And Catalogs

`packs_list`
```json
{}
```

`packs_set_active`
```json
{
  "pack_name": "default-pack",
  "active": true
}
```

`algorithms_list`
```json
{}
```

`catalogs_list`
```json
{
  "exclude_hyphenated_dlls": false,
  "common_windows_dlls_only": true,
  "filter_text": "kernel",
  "sort_by": "name",
  "sort_direction": "asc"
}
```

## HashDB-Compatible

`hashdb_algorithms`
```json
{}
```

`hashdb_lookup`
```json
{
  "algorithm_id": "ror13_add",
  "hash_value": "0x7c0017bb",
  "xor_value": "0x0"
}
```

`hashdb_module_hashes`
```json
{
  "module_name": "kernel32.dll",
  "algorithm_id": "ror13_add",
  "permutation": ""
}
```

`hashdb_hunt`
```json
{
  "hashes": "0x7c0017bb,0x5a3a18a5",
  "xor_value": "0x0"
}
```

## Resolve And Search

`resolve_hash`
```json
{
  "hash_value": "0x7c0017bb",
  "algorithm_id": "ror13_add",
  "library_names": "kernel32.dll",
  "catalog_names": "",
  "xor_value": "0x0",
  "algorithm_params_json": "{\"base_values\":[\"0x10\",\"0x20\"]}",
  "exclude_hyphenated_dlls": false,
  "common_windows_dlls_only": true
}
```

`search_hash`
```json
{
  "hash_value": "0x7c0017bb",
  "algorithm_id": "",
  "library_name": "",
  "library_names": "kernel32.dll,user32.dll",
  "catalog_names": "",
  "xor_value": "0x0",
  "algorithm_params_json": "{\"base_values\":[\"0x10\",\"0x20\"]}",
  "exclude_hyphenated_dlls": false,
  "common_windows_dlls_only": true
}
```

`hash_string`
```json
{
  "algorithm_id": "ror13_add",
  "symbol_name": "GetProcAddress",
  "library_name": "kernel32.dll",
  "library_names": "",
  "catalog_names": "",
  "xor_value": "0x0",
  "algorithm_params_json": "{\"base_values\":[\"0x10\",\"0x20\"]}"
}
```

`export_enum`
```json
{
  "algorithm_id": "ror13_add",
  "library_name": "kernel32.dll",
  "library_names": "",
  "catalog_names": "",
  "xor_value": "0x0",
  "algorithm_params_json": "{\"base_values\":[\"0x10\",\"0x20\"]}"
}
```

`bulk_auto`
```json
{
  "hash_value": "0x7c0017bb",
  "algorithm_id": "ror13_add",
  "library_names": "kernel32.dll,user32.dll",
  "catalog_names": "",
  "xor_value": "0x0",
  "algorithm_params_json": "{\"base_values\":[\"0x10\",\"0x20\"]}",
  "exclude_hyphenated_dlls": false,
  "common_windows_dlls_only": true
}
```

## File-Based Tools

`analyze_binary_file`
```json
{
  "file_path": "/home/fxb/samples/kernel32.dll"
}
```

`build_catalogs_from_files`
```json
{
  "file_paths": [
    "/home/fxb/samples/kernel32.dll",
    "/home/fxb/samples/user32.dll"
  ]
}
```

## Authoring Tools

`validate_pack`
```json
{
  "pack_path": "packs/default-pack"
}
```

`scaffold_algorithm`
```json
{
  "pack_path": "packs/default-pack",
  "algorithm_id": "custom_crc32_variant",
  "language": "python"
}
```

## CLI-Scope Helpers

`cli_init_workspace`
```json
{
  "workspace": "/tmp/apihashing-workspace",
  "pack_name": "team-pack",
  "no_bundled_packs": false
}
```

`cli_build_catalog`
```json
{
  "input_paths": [
    "/home/fxb/samples/System32"
  ]
}
```
