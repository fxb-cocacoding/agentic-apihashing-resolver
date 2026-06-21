from __future__ import annotations

from pathlib import Path

from apihashing.core.service import ApiHashService
from apihashing.core.workspace import init_workspace


def test_service_falls_back_to_bundled_packs_when_workspace_has_no_local_packs(tmp_path: Path) -> None:
    service = ApiHashService.from_project_root(tmp_path)
    algorithm_ids = {item.id for item in service.list_algorithms()}
    assert "payouts_king_crc32" in algorithm_ids


def test_init_workspace_copies_bundled_packs_by_default(tmp_path: Path) -> None:
    result = init_workspace(tmp_path / "isolated", pack_name="team-pack")
    copied = {path.name for path in result.copied_bundled_pack_paths}
    assert "default-pack" in copied
    assert "oalabs-hashdb" in copied
    assert (result.created_pack_path / "algorithms" / "python").exists()


def test_mp_search_env_flag_defaults_to_enabled(monkeypatch) -> None:
    monkeypatch.delenv("APIHASHING_ENABLE_MP_SEARCH", raising=False)
    assert ApiHashService._env_flag("APIHASHING_ENABLE_MP_SEARCH", default=True) is True
    monkeypatch.setenv("APIHASHING_ENABLE_MP_SEARCH", "0")
    assert ApiHashService._env_flag("APIHASHING_ENABLE_MP_SEARCH", default=True) is False


def test_mp_search_worker_cap_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("APIHASHING_MP_SEARCH_MAX_WORKERS", "2")
    assert ApiHashService._process_pool_worker_count(10) == 2
