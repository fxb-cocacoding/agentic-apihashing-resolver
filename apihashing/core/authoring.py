from __future__ import annotations

from pathlib import Path

TEMPLATES_ROOT = Path(__file__).resolve().parents[1] / "templates"


def _load_template(*relative_parts: str) -> str:
    return (TEMPLATES_ROOT.joinpath(*relative_parts)).read_text(encoding="utf-8")


PYTHON_TEMPLATE = _load_template("algorithms", "python", "algorithm.hash.py.tmpl")
C_TEMPLATE = _load_template("algorithms", "c", "algorithm.hash.c.tmpl")

VECTORS_TEMPLATE = '''{
  "vectors": [
    {
      "library": "example.dll",
      "symbol": "ExampleFunction",
      "hash": "00000000"
    }
  ]
}
'''


def scaffold_algorithm(pack_path: Path, algorithm_id: str, language: str) -> tuple[Path, Path]:
    tests_dir = pack_path / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    if language == "python":
        algorithms_dir = pack_path / "algorithms"
        algorithms_dir.mkdir(parents=True, exist_ok=True)
        algorithm_path = algorithms_dir / f"{algorithm_id}.hash.py"
        algorithm_path.write_text(PYTHON_TEMPLATE.format(algorithm_id=algorithm_id), encoding="utf-8")
    elif language == "c":
        native_dir = pack_path / "algorithms" / "native"
        native_dir.mkdir(parents=True, exist_ok=True)
        algorithm_path = native_dir / f"{algorithm_id}.hash.c"
        algorithm_path.write_text(C_TEMPLATE, encoding="utf-8")
    else:
        raise ValueError(f"Unsupported language: {language}")
    vectors_path = tests_dir / f"{algorithm_id}_vectors.json"
    vectors_path.write_text(VECTORS_TEMPLATE, encoding="utf-8")
    return algorithm_path, vectors_path
