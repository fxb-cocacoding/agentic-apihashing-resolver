import tomllib
from pathlib import Path


def test_setuptools_package_discovery_is_limited_to_apihashing() -> None:
    data = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))

    include = data['tool']['setuptools']['packages']['find']['include']
    package_data = data['tool']['setuptools']['package-data']['apihashing']
    scripts = data['project']['scripts']

    assert include == ['apihashing*']
    assert 'bundled_packs/**/*' in package_data
    assert scripts['apihashing'] == 'apihashing.cli:main'
    assert scripts['apihashing-mcp'] == 'apihashing.mcp_server:main'
