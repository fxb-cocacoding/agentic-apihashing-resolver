import shutil
import subprocess
from pathlib import Path

from apihashing.core.service import ApiHashService


def test_service_loads_multiple_c_algorithms_from_shared_object_without_yaml(tmp_path: Path) -> None:
    if shutil.which("gcc") is None:
        raise AssertionError("gcc is required for this test")

    fixture_dir = Path(__file__).parent / "fixtures" / "native_pack_template"
    pack_dir = tmp_path / "native-pack"
    shutil.copytree(fixture_dir, pack_dir)
    library_path = pack_dir / "algorithms" / "native" / "native_bundle.hash.so"

    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            str(pack_dir / "algorithms" / "native" / "native_bundle.hash.c"),
            "-o",
            str(library_path),
        ],
        check=True,
    )

    service = ApiHashService(pack_roots=[pack_dir])
    algorithm_ids = {item.id for item in service.list_algorithms()}
    first = service.resolve_hash(0xAABBCCDD, algorithm_id="native_demo")
    second = service.resolve_hash(0x1122334455667788, algorithm_id="native_demo64")

    assert {"native_demo", "native_demo64"}.issubset(algorithm_ids)
    assert len(first.matches) == 1
    assert first.matches[0].symbol == "DemoFunction"
    assert first.matches[0].hash_value_hex == "aabbccdd"
    assert len(second.matches) == 1
    assert second.matches[0].symbol == "WideFunction"
    assert second.matches[0].hash_size_bits == 64
    assert second.matches[0].hash_value_hex == "1122334455667788"
