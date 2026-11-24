import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "failsafe"
BLINDED_PACKAGES = ("inference", "probe")
FORBIDDEN_MODULE_WORDS = ("oracle",)
FORBIDDEN_NAMES = ("ServerStateSnapshot",)
ALLOWED_CLIENT_MODULES = ("kanidm_oracle", "zitadel_oracle")


def _py_files(package: str):
    return sorted((SRC / package).rglob("*.py"))


def _violations(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_CLIENT_MODULES and any(w in alias.name for w in FORBIDDEN_MODULE_WORDS):
                    found.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if any(w in module for w in FORBIDDEN_MODULE_WORDS):
                found.append(f"from {module} import ...")
            for alias in node.names:
                if alias.name in FORBIDDEN_NAMES:
                    found.append(f"from {module} import {alias.name}")
    return found


def test_inference_package_is_actually_scanned():
    assert len(_py_files("inference")) > 0, f"검사 대상 파일이 없음: {SRC / 'inference'}"


@pytest.mark.parametrize("package", BLINDED_PACKAGES)
def test_blinded_packages_do_not_touch_ground_truth(package):
    if not (SRC / package).exists():
        pytest.skip(f"{package} 패키지가 아직 없음")
    bad = {str(p.relative_to(SRC)): v for p in _py_files(package) if (v := _violations(p))}
    assert not bad, f"판별기 쪽에서 정답 쪽을 import함: {bad}"
