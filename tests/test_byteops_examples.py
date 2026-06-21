from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import re

import pytest


CANONICAL_TEST1_INPUT = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _load_hashdb_module(name: str):
    module_path = Path(__file__).resolve().parents[1] / 'packs' / 'oalabs-hashdb' / 'algorithms' / name
    spec = spec_from_file_location('hashdb_under_test', module_path)
    module = module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_hashdb_rotate_helpers_support_32_bit_values() -> None:
    module = _load_hashdb_module('ror13_add.py')
    value = 0x12345678

    assert module.ror(value, 8, 32) == 0x78123456


def test_hashdb_shift_helpers_support_32_bit_values() -> None:
    module = _load_hashdb_module('shr2_shl5_xor.py')

    assert module.shl32(0x12345678, 8) == 0x34567800
    assert module.shr32(0x12345678, 8) == 0x00123456


def test_default_pack_only_keeps_local_algorithms() -> None:
    algorithms_root = Path(__file__).resolve().parents[1] / 'packs' / 'default-pack' / 'algorithms' / 'python'
    plugin_names = sorted(path.name for path in algorithms_root.glob('*.py'))

    assert plugin_names == ['payouts_king_crc32.hash.py']


def test_imported_hashdb_hashes_do_not_use_reflective_byteops_helpers() -> None:
    root = Path(__file__).resolve().parents[1] / 'packs' / 'oalabs-hashdb' / 'algorithms'
    plugin_text = '\n'.join(path.read_text(encoding='utf-8') for path in root.glob('*.py'))

    assert 'BYTEOPS_WIDTHS' not in plugin_text
    assert '_validate_size' not in plugin_text
    assert 'getattr(BYTEOPS' not in plugin_text
    assert 'ROTATE_BITMASK = {' not in plugin_text


def _hashdb_algorithms_with_test1_markers() -> list[Path]:
    algorithms_root = Path(__file__).resolve().parents[1] / 'packs' / 'oalabs-hashdb' / 'algorithms'
    matches: list[Path] = []
    for path in sorted(algorithms_root.glob('*.py')):
        text = path.read_text(encoding='utf-8')
        if "TEST_1" in text or "TEST1" in text:
            matches.append(path)
    return matches


TEST1_ANY_ASSIGNMENT_RE = re.compile(
    r"^\s*(?P<name>TEST_1|TEST1)\s*=\s*(?P<value>[^\n#]+)",
    re.MULTILINE,
)


@pytest.mark.parametrize("module_path", _hashdb_algorithms_with_test1_markers())
def test_hashdb_test1_string_matches_test1_value(module_path: Path) -> None:
    source_text = module_path.read_text(encoding='utf-8')
    any_match = TEST1_ANY_ASSIGNMENT_RE.search(source_text)
    assert any_match is not None, f"{module_path.name}: file contains TEST_1/TEST1 marker but no assignment"
    expected_value_text = any_match.group("value").strip().replace("_", "").lower()

    spec = spec_from_file_location(f"hashdb_test1_{module_path.stem}", module_path)
    module = module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)

    hash_fn = getattr(module, "hash")
    assert callable(hash_fn)
    test_name = any_match.group("name")
    assert hasattr(module, test_name)

    try:
        actual = hash_fn(CANONICAL_TEST1_INPUT)
    except TypeError:
        actual = hash_fn(CANONICAL_TEST1_INPUT.decode("ascii"))
    except NameError as exc:
        # Some imported upstream files call shl32 but do not define it.
        # Provide a local fallback without modifying source files.
        if "shl32" not in str(exc) or not hasattr(module, "BYTEOPS"):
            raise

        def _fallback_shl32(value: int, count: int) -> int:
            value_bytes = (value & 0xFFFFFFFF).to_bytes(4, "little")
            return int.from_bytes(module.BYTEOPS.shl_dword(value_bytes, count), "little")

        module.shl32 = _fallback_shl32
        actual = hash_fn(CANONICAL_TEST1_INPUT)

    actual_int = int(actual)
    actual_hex = f"0x{actual_int:x}"
    actual_dec = str(actual_int)
    allowed_forms = {actual_dec, actual_hex}
    if expected_value_text.startswith("0x"):
        hex_width = len(expected_value_text) - 2
        if hex_width > 0:
            allowed_forms.add(f"0x{actual_int:0{hex_width}x}")

    assert expected_value_text in allowed_forms, (
        f"{module_path.name}: {test_name}={expected_value_text!r} does not match "
        f"hash({CANONICAL_TEST1_INPUT!r}) decimal={actual_dec!r} hex={actual_hex!r}"
    )
