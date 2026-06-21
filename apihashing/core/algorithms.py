from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import io
from pathlib import Path
import shutil
import tempfile
from types import ModuleType
from contextlib import redirect_stdout

from apihashing.core.models import AlgorithmMetadata
from apihashing.plugin_api import FunctionHashImplementation, HashImplementation, HashInput, HashValue


class LoadedAlgorithm:
    def __init__(self, metadata: AlgorithmMetadata, implementation: HashImplementation) -> None:
        self.metadata = metadata
        self.implementation = implementation

    def compute(self, library: str, symbol: str, params: dict[str, object] | None = None) -> HashValue:
        return self.implementation.compute(HashInput(library_name=library, symbol_name=symbol, params=params or {}))


class AlgorithmRegistry:
    def __init__(self) -> None:
        self._algorithms: dict[str, LoadedAlgorithm] = {}
        self._aliases: dict[str, str] = {}

    def register(self, algorithm: LoadedAlgorithm) -> None:
        if algorithm.metadata.id in self._algorithms:
            return
        self._algorithms[algorithm.metadata.id] = algorithm
        for alias in algorithm.metadata.aliases:
            self._aliases.setdefault(alias, algorithm.metadata.id)

    def get(self, algorithm_id: str) -> LoadedAlgorithm:
        canonical = self._aliases.get(algorithm_id, algorithm_id)
        return self._algorithms[canonical]

    def list(self) -> list[AlgorithmMetadata]:
        return [algorithm.metadata for algorithm in self._algorithms.values()]


class NativeFunctionImplementation(HashImplementation):
    def __init__(self, *, metadata: AlgorithmMetadata, callback) -> None:
        self.id = metadata.id
        self.display_name = metadata.display_name
        self.description = metadata.description
        self.input_mode = metadata.input_mode
        self.hash_size_bits = metadata.hash_size_bits
        self.author = metadata.author
        self.source = metadata.source
        self.license = metadata.license
        self.implementation_type = "c_shared"
        self.supports_base_values = metadata.supports_base_values
        self._callback = callback

    def compute(self, data: HashInput) -> HashValue:
        value = int(self._callback(data.library_name, data.symbol_name))
        return HashValue.from_int(value, self.hash_size_bits)


class NativeDescriptor(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_char_p),
        ("display_name", ctypes.c_char_p),
        ("description", ctypes.c_char_p),
        ("input_mode", ctypes.c_char_p),
        ("hash_size_bits", ctypes.c_uint32),
        ("source", ctypes.c_char_p),
        ("license", ctypes.c_char_p),
        ("symbol_name", ctypes.c_char_p),
    ]


def _module_name(module_path: Path) -> str:
    digest = hashlib.sha1(str(module_path).encode("utf-8")).hexdigest()[:12]
    return f"apihashing_plugin_{digest}"


def _native_load_path(module_path: Path) -> Path:
    stat = module_path.stat()
    digest = hashlib.sha1(str(module_path.resolve()).encode("utf-8")).hexdigest()[:12]
    cache_root = Path(tempfile.gettempdir()) / "apihashing_native"
    cache_root.mkdir(parents=True, exist_ok=True)
    target_name = f"{module_path.name}.{digest}.{stat.st_mtime_ns}"
    target_path = cache_root / target_name
    if not target_path.exists():
        shutil.copy2(module_path, target_path)
    return target_path


def _metadata_from_implementation(implementation: HashImplementation, pack_name: str, module_path: Path) -> AlgorithmMetadata:
    implementation_type = implementation.implementation_type
    if implementation_type not in {"python", "c_shared"}:
        raise ValueError(f"Unsupported implementation type: {implementation_type}")
    return AlgorithmMetadata(
        id=implementation.id,
        display_name=implementation.display_name or implementation.id,
        implementation_type=implementation_type,
        input_mode=implementation.input_mode,
        hash_size_bits=implementation.hash_size_bits,
        supports_base_values=bool(getattr(implementation, "supports_base_values", False)),
        description=implementation.description,
        author=getattr(implementation, "author", None),
        source=implementation.source,
        license=implementation.license,
        aliases=list(getattr(implementation, "aliases", ()) or ()),
        copied_from_flare_shellcode=bool(getattr(implementation, "copied_from_flare_shellcode", False)),
        pack=pack_name,
        module_path=str(module_path),
    )


def _hashdb_type_to_bits(type_name: str | None) -> int | None:
    if type_name == "unsigned_int":
        return 32
    if type_name == "unsigned_long":
        return 64
    return None


def _build_hashdb_input(module: ModuleType, library_name: str, symbol_name: str) -> bytes:
    sample = getattr(module, "TEST_API_DATA_1", None)
    if sample is None:
        return symbol_name.encode("utf-8")

    sample_bytes = sample.encode("latin1") if isinstance(sample, str) else bytes(sample)
    library_bytes = library_name.encode("utf-8")
    symbol_bytes = symbol_name.encode("utf-8")

    if b"\x00\x00\x00" in sample_bytes:
        module_part = library_name.upper().encode("utf-16le") + b"\x00\x00"
        return module_part + symbol_bytes + b"\x00"

    if b".dll" in sample_bytes.lower():
        return library_bytes + symbol_bytes

    return symbol_bytes


def _infer_author(source: str | None, copied_from_flare_shellcode: bool) -> str | None:
    if source and "github.com/OALabs/hashdb" in source:
        return "OALabs/hashdb contributors"
    if copied_from_flare_shellcode:
        return "Mandiant FLARE"
    if source and "zscaler.com" in source:
        return "Zscaler ThreatLabz"
    return None


def _build_hashdb_implementation(module: ModuleType, module_path: Path, pack_name: str) -> HashImplementation | None:
    hash_fn = getattr(module, "hash", None)
    if not callable(hash_fn):
        return None

    algorithm_id = getattr(module, "ID", module_path.stem)
    display_name = getattr(module, "DISPLAY_NAME", algorithm_id)
    description = getattr(module, "DESCRIPTION", "") or ""
    hash_size_bits = _hashdb_type_to_bits(getattr(module, "TYPE", None))
    source = getattr(module, "SOURCE", None)
    license_name = getattr(module, "LICENSE", None)
    author = getattr(module, "AUTHOR", None)
    aliases = tuple(alias for alias in getattr(module, "ALIASES", ()) if isinstance(alias, str))
    copied_from_flare_shellcode = bool(getattr(module, "COPIED_FROM_FLARE_SHELLCODE", False))
    if not copied_from_flare_shellcode and 'https://github.com/mandiant/flare-ida/blob/master/shellcode_hashes/make_sc_hash_db.py' in module_path.read_text():
        copied_from_flare_shellcode = True
    if not author:
        author = _infer_author(source, copied_from_flare_shellcode)

    def _is_noisy_hash_function() -> bool:
        probe_input = _build_hashdb_input(module, "kernel32.dll", "GetProcAddress")
        with io.StringIO() as sink, redirect_stdout(sink):
            try:
                hash_fn(probe_input)
            except Exception:
                return bool(sink.getvalue())
            return bool(sink.getvalue())

    suppress_stdout = _is_noisy_hash_function()

    if suppress_stdout:
        def callback(library_name: str, symbol_name: str):
            with io.StringIO() as sink, redirect_stdout(sink):
                return hash_fn(_build_hashdb_input(module, library_name, symbol_name))
    else:
        def callback(library_name: str, symbol_name: str):
            return hash_fn(_build_hashdb_input(module, library_name, symbol_name))

    return FunctionHashImplementation(
        id=algorithm_id,
        display_name=display_name,
        callback=callback,
        description=description,
        hash_size_bits=hash_size_bits,
        author=author,
        source=source,
        license=license_name,
        aliases=aliases,
        copied_from_flare_shellcode=copied_from_flare_shellcode,
    )


def load_python_algorithms(module_path: Path, pack_name: str) -> list[LoadedAlgorithm]:
    spec = importlib.util.spec_from_file_location(_module_name(module_path), module_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Unable to load Python algorithm from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    discovered: list[HashImplementation] = []
    if hasattr(module, "HASH_IMPLEMENTATION"):
        discovered.append(getattr(module, "HASH_IMPLEMENTATION"))
    if hasattr(module, "HASH_IMPLEMENTATIONS"):
        discovered.extend(getattr(module, "HASH_IMPLEMENTATIONS"))
    if not discovered:
        hashdb_implementation = _build_hashdb_implementation(module, module_path, pack_name)
        if hashdb_implementation is not None:
            discovered.append(hashdb_implementation)
    if not discovered:
        raise ValueError(f"Python plugin {module_path} must export HASH_IMPLEMENTATION, HASH_IMPLEMENTATIONS, or a HashDB-style hash(data) function")

    loaded: list[LoadedAlgorithm] = []
    for implementation in discovered:
        if not isinstance(implementation, HashImplementation):
            raise TypeError(f"Plugin exported unsupported implementation object: {type(implementation)!r}")
        metadata = _metadata_from_implementation(implementation, pack_name, module_path)
        loaded.append(LoadedAlgorithm(metadata=metadata, implementation=implementation))
    return loaded


def load_native_algorithms(module_path: Path, pack_name: str) -> list[LoadedAlgorithm]:
    # Load native plugins from a versioned temp copy to avoid stale dlopen handles
    # when a .hash.so is rebuilt in place during hot-reload workflows.
    library = ctypes.CDLL(str(_native_load_path(module_path)))
    count_fn = getattr(library, "apihash_plugin_count")
    count_fn.argtypes = []
    count_fn.restype = ctypes.c_uint32
    descriptor_fn = getattr(library, "apihash_plugin_descriptor")
    descriptor_fn.argtypes = [ctypes.c_uint32]
    descriptor_fn.restype = ctypes.POINTER(NativeDescriptor)
    author_fn = getattr(library, "apihash_plugin_author", None)
    if author_fn is not None:
        author_fn.argtypes = [ctypes.c_uint32]
        author_fn.restype = ctypes.c_char_p

    loaded: list[LoadedAlgorithm] = []
    for index in range(int(count_fn())):
        descriptor_ptr = descriptor_fn(index)
        if not descriptor_ptr:
            continue
        descriptor = descriptor_ptr.contents
        symbol_name = descriptor.symbol_name.decode("utf-8")
        callback = getattr(library, symbol_name)
        callback.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        callback.restype = ctypes.c_uint64
        author: str | None = None
        if author_fn is not None:
            author_raw = author_fn(index)
            if author_raw:
                author = author_raw.decode("utf-8")
        metadata = AlgorithmMetadata(
            id=descriptor.id.decode("utf-8"),
            display_name=descriptor.display_name.decode("utf-8"),
            implementation_type="c_shared",
            input_mode=descriptor.input_mode.decode("utf-8"),
            hash_size_bits=int(descriptor.hash_size_bits) or None,
            supports_base_values=False,
            description=descriptor.description.decode("utf-8") if descriptor.description else "",
            author=author,
            source=descriptor.source.decode("utf-8") if descriptor.source else None,
            license=descriptor.license.decode("utf-8") if descriptor.license else None,
            aliases=[],
            copied_from_flare_shellcode=False,
            pack=pack_name,
            module_path=str(module_path),
        )

        def wrapper(library_name: str, symbol_name_value: str, func=callback) -> int:
            return int(func(library_name.encode("utf-8"), symbol_name_value.encode("utf-8")))

        implementation = NativeFunctionImplementation(metadata=metadata, callback=wrapper)
        loaded.append(LoadedAlgorithm(metadata=metadata, implementation=implementation))
    return loaded
