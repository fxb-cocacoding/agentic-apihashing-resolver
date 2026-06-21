from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from inspect import signature
from typing import Callable


@dataclass(frozen=True)
class HashInput:
    library_name: str
    symbol_name: str
    params: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class HashValue:
    value_bytes: bytes
    bit_length: int

    @classmethod
    def from_int(cls, value: int, bit_length: int | None = None) -> "HashValue":
        normalized = int(value)
        if normalized < 0:
            raise ValueError("Hash values must be unsigned")
        if bit_length is None:
            bit_length = max(normalized.bit_length(), 8)
        byte_length = max((bit_length + 7) // 8, 1)
        return cls(value_bytes=normalized.to_bytes(byte_length, "big"), bit_length=bit_length)

    @classmethod
    def from_bytes(cls, value: bytes, bit_length: int | None = None) -> "HashValue":
        if bit_length is None:
            bit_length = max(len(value) * 8, 8)
        return cls(value_bytes=bytes(value), bit_length=bit_length)

    def to_unsigned_int(self) -> int:
        return int.from_bytes(self.value_bytes, "big")

    def to_hex(self) -> str:
        return self.value_bytes.hex()


class HashImplementation(ABC):
    id: str
    display_name: str | None = None
    description: str = ""
    input_mode: str = "library_function"
    hash_size_bits: int | None = 32
    author: str | None = None
    source: str | None = None
    license: str | None = None
    implementation_type: str = "python"
    aliases: tuple[str, ...] = ()
    copied_from_flare_shellcode: bool = False
    supports_base_values: bool = False

    @abstractmethod
    def compute(self, data: HashInput) -> HashValue:
        raise NotImplementedError


HashCallback = Callable[..., HashValue | int | bytes]


class FunctionHashImplementation(HashImplementation):
    def __init__(
        self,
        *,
        id: str,
        callback: HashCallback,
        display_name: str | None = None,
        description: str = "",
        input_mode: str = "library_function",
        hash_size_bits: int | None = 32,
        author: str | None = None,
        source: str | None = None,
        license: str | None = None,
        aliases: tuple[str, ...] = (),
        copied_from_flare_shellcode: bool = False,
        supports_base_values: bool | None = None,
    ) -> None:
        self.id = id
        self.display_name = display_name or id
        self.callback = callback
        self._callback_arity = len(signature(self.callback).parameters)
        self.description = description
        self.input_mode = input_mode
        self.hash_size_bits = hash_size_bits
        self.author = author
        self.source = source
        self.license = license
        self.implementation_type = "python"
        self.aliases = aliases
        self.copied_from_flare_shellcode = copied_from_flare_shellcode
        self.supports_base_values = self._callback_arity > 2 if supports_base_values is None else supports_base_values

    def compute(self, data: HashInput) -> HashValue:
        if self._callback_arity <= 2:
            result = self.callback(data.library_name, data.symbol_name)
        else:
            result = self.callback(data.library_name, data.symbol_name, data.params)
        if isinstance(result, HashValue):
            return result
        if isinstance(result, int):
            return HashValue.from_int(result, self.hash_size_bits)
        if isinstance(result, bytes):
            return HashValue.from_bytes(result, self.hash_size_bits)
        raise TypeError(f"Unsupported hash result type: {type(result)!r}")
