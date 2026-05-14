"""Generate the Homebrew formula for the latest PyPI release."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

PYPI_BASE_URL = "https://pypi.org/pypi"
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^;\s]+)")
FORMULA_DESC = "API recon: preflight defenses, traffic capture, and spec extraction"


@dataclass(frozen=True)
class Distribution:
    name: str
    version: str
    url: str
    sha256: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create or update Formula/apisniff.rb in the Homebrew tap.",
    )
    parser.add_argument("--version", help="Release version without the leading v tag")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--tap-root", type=Path, required=True)
    parser.add_argument("--formula-path", default="Formula/apisniff.rb")
    parser.add_argument("--python-version", default="3.13")
    parser.add_argument("--python-platform", default="aarch64-apple-darwin")
    parser.add_argument(
        "--pypi-timeout",
        type=int,
        default=180,
        help="Seconds to wait for the just-published apisniff release to appear on PyPI.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the formula without writing it",
    )
    return parser.parse_args()


def load_project(project_root: Path) -> dict:
    with (project_root / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)
    return pyproject["project"]


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def fetch_release(project: str, version: str, retry_seconds: int = 0) -> dict:
    url = f"{PYPI_BASE_URL}/{canonical_name(project)}/{version}/json"
    deadline = time.monotonic() + retry_seconds
    last_error: Exception | None = None

    while True:
        try:
            return fetch_json(url)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            last_error = error
        except urllib.error.URLError as error:
            last_error = error

        if time.monotonic() >= deadline:
            break
        time.sleep(10)

    raise RuntimeError(f"PyPI release not available after {retry_seconds}s: {url}") from last_error


def select_distribution(project: str, version: str, retry_seconds: int = 0) -> Distribution:
    release = fetch_release(project, version, retry_seconds)
    files = release["urls"]

    sdists = [file for file in files if file["packagetype"] == "sdist"]
    if sdists:
        file = sorted(sdists, key=lambda item: item["filename"])[0]
        return Distribution(project, version, file["url"], file["digests"]["sha256"])

    universal_wheels = [
        file for file in files if file["filename"].endswith("-py3-none-any.whl")
    ]
    if universal_wheels:
        file = sorted(universal_wheels, key=lambda item: item["filename"])[0]
        return Distribution(project, version, file["url"], file["digests"]["sha256"])

    filenames = ", ".join(file["filename"] for file in files)
    raise RuntimeError(
        f"No sdist or universal wheel found for {project} {version}. Available files: {filenames}"
    )


def compile_requirements(
    project_root: Path,
    python_version: str,
    python_platform: str,
) -> list[tuple[str, str]]:
    command = [
        "uv",
        "pip",
        "compile",
        "pyproject.toml",
        "--no-header",
        "--no-annotate",
        "--no-emit-index-url",
        "--python-version",
        python_version,
        "--python-platform",
        python_platform,
    ]
    result = subprocess.run(
        command,
        cwd=project_root,
        check=True,
        text=True,
        capture_output=True,
    )

    requirements: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        match = REQUIREMENT_RE.match(line.strip())
        if match:
            requirements.append((canonical_name(match.group(1)), match.group(2)))

    if not requirements:
        raise RuntimeError("uv did not produce any pinned requirements")
    return requirements


def ruby_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def project_license(project: dict) -> str:
    license_value = project.get("license", "")
    if isinstance(license_value, str):
        return license_value
    if isinstance(license_value, dict):
        return license_value.get("text", "")
    return ""


def build_formula(
    project: dict,
    package: Distribution,
    resources: list[Distribution],
    python_formula: str,
) -> str:
    homepage = project.get("urls", {}).get("Homepage", "")
    lines = [
        "# frozen_string_literal: true",
        "",
        "class Apisniff < Formula",
        "  include Language::Python::Virtualenv",
        "",
        f'  desc "{ruby_string(FORMULA_DESC)}"',
        f'  homepage "{ruby_string(homepage)}"',
        f'  url "{ruby_string(package.url)}"',
        f'  sha256 "{package.sha256}"',
        f'  license "{ruby_string(project_license(project))}"',
        "",
        '  depends_on "pkgconf" => :build',
        '  depends_on "rust" => :build',
        f'  depends_on "{python_formula}"',
        "",
    ]

    for resource in resources:
        lines.extend(
            [
                f'  resource "{resource.name}" do',
                f'    url "{ruby_string(resource.url)}"',
                f'    sha256 "{resource.sha256}"',
                "  end",
                "",
            ]
        )

    lines.extend(
        [
            "  def install",
            f'    virtualenv_install_with_resources(using: "{python_formula}")',
            "  end",
            "",
            "  test do",
            '    assert_match "Usage", shell_output("#{bin}/apisniff --help")',
            "  end",
            "end",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    project_root = args.project_root.resolve()
    tap_root = args.tap_root.resolve()
    project = load_project(project_root)
    version = args.version or project["version"]
    python_formula = f"python@{args.python_version}"

    package = select_distribution(project["name"], version, args.pypi_timeout)
    requirements = compile_requirements(
        project_root,
        args.python_version,
        args.python_platform,
    )
    resources = [
        select_distribution(name, pinned_version)
        for name, pinned_version in requirements
        if canonical_name(name) != canonical_name(project["name"])
    ]
    formula = build_formula(project, package, resources, python_formula)

    if args.dry_run:
        print(formula)
        return 0

    formula_path = tap_root / args.formula_path
    formula_path.parent.mkdir(parents=True, exist_ok=True)
    formula_path.write_text(formula)
    print(f"Wrote {formula_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
