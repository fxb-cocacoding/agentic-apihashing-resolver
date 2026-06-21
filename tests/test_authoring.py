import asyncio
from pathlib import Path

import httpx

from apihashing.app import create_app


async def _request(app, method: str, url: str, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.request(method, url, **kwargs)


def test_validate_pack_accepts_default_pack() -> None:
    app = create_app(Path(__file__).resolve().parents[1])

    response = asyncio.run(_request(app, "POST", "/validate-pack", json={"pack_path": "packs/default-pack"}))

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is True
    assert payload["errors"] == []


def test_scaffold_algorithm_creates_python_template_without_yaml(tmp_path: Path) -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    pack_dir = tmp_path / "custom-pack"
    pack_dir.mkdir()

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/scaffold/algorithm",
            json={
                "pack_path": str(pack_dir),
                "algorithm_id": "demo_hash",
                "language": "python",
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_path"].endswith("algorithms/demo_hash.hash.py")
    assert (pack_dir / "algorithms" / "demo_hash.hash.py").exists()
    assert (pack_dir / "tests" / "demo_hash_vectors.json").exists()


def test_scaffold_algorithm_creates_c_template_without_yaml(tmp_path: Path) -> None:
    app = create_app(Path(__file__).resolve().parents[1])
    pack_dir = tmp_path / "custom-pack-c"
    pack_dir.mkdir()

    response = asyncio.run(
        _request(
            app,
            "POST",
            "/scaffold/algorithm",
            json={
                "pack_path": str(pack_dir),
                "algorithm_id": "demo_hash_native",
                "language": "c",
            },
        )
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["algorithm_path"].endswith("algorithms/native/demo_hash_native.hash.c")
    assert (pack_dir / "algorithms" / "native" / "demo_hash_native.hash.c").exists()
    assert (pack_dir / "tests" / "demo_hash_native_vectors.json").exists()
