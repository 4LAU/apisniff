from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_homebrew_module():
    script_path = Path(__file__).parents[1] / "scripts" / "update_homebrew_formula.py"
    spec = importlib.util.spec_from_file_location("update_homebrew_formula", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["update_homebrew_formula"] = module
    spec.loader.exec_module(module)
    return module


def test_build_formula_uses_homebrew_safe_description() -> None:
    homebrew = load_homebrew_module()
    package = homebrew.Distribution(
        name="apisniff",
        version="0.1.0",
        url="https://files.pythonhosted.org/packages/apisniff-0.1.0.tar.gz",
        sha256="a" * 64,
    )
    resource = homebrew.Distribution(
        name="httpx",
        version="0.28.1",
        url="https://files.pythonhosted.org/packages/httpx-0.28.1.tar.gz",
        sha256="b" * 64,
    )

    formula = homebrew.build_formula(
        {
            "description": (
                "One tool for API recon: preflight defenses, capture real traffic, "
                "extract a usable spec."
            ),
            "license": "MIT",
            "urls": {"Homepage": "https://github.com/4LAU/apisniff"},
        },
        package,
        [resource],
        "python@3.13",
    )

    desc_line = next(line for line in formula.splitlines() if line.strip().startswith("desc "))
    desc = desc_line.split('"', 2)[1]
    assert desc == "API recon: preflight defenses, traffic capture, and spec extraction"
    assert len(desc) <= 80
    assert not desc.endswith(".")

    assert 'resource "httpx" do' in formula
    assert 'depends_on "python@3.13"' in formula
    assert 'virtualenv_install_with_resources(using: "python@3.13")' in formula
