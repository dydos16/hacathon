from pathlib import Path

from repropack.analysis import analyze
from repropack.intake import read_directory

EXAMPLES = Path(__file__).parent.parent / "examples"


def deps_of(files):
    return {d.module: d for d in analyze(files).dependencies}


def test_separates_stdlib_local_and_external():
    deps = deps_of(read_directory(EXAMPLES / "local_module_project"))
    assert deps["helpers"].category == "local"
    assert all(d.category in ("stdlib", "local") for d in deps.values())

def test_maps_renamed_modules_to_pypi_packages():
    deps = deps_of({"a.py": b"import sklearn, cv2, yaml\nfrom PIL import Image\n"})
    assert {m: d.package for m, d in deps.items()} == {
        "sklearn": "scikit-learn", "cv2": "opencv-python", "yaml": "PyYAML", "PIL": "Pillow"}
    assert not any(d.needs_confirmation for d in deps.values())


def test_ambiguous_and_unknown_modules_need_confirmation():
    deps = deps_of({"a.py": b"import jwt\nimport labtools_internal\n"})
    assert deps["jwt"].needs_confirmation and deps["jwt"].candidates == ("PyJWT", "jwt")
    assert deps["labtools_internal"].status == "догадка" and deps["labtools_internal"].needs_confirmation


def test_declared_requirements_resolve_ambiguity_and_versions():
    files = {"a.py": b"import jwt\nimport numpy\n", "requirements.txt": b"PyJWT==2.8.0\nnumpy>=1.26 # comment\n"}
    deps = deps_of(files)
    assert (deps["jwt"].package, deps["jwt"].version, deps["jwt"].needs_confirmation) == ("PyJWT", "==2.8.0", False)
    assert deps["numpy"].version == ">=1.26"


def test_pyproject_and_environment_yml_are_read():
    pyproject = b'[project]\nrequires-python = ">=3.10"\ndependencies = ["scipy==1.13.0"]\n'
    conda = b"dependencies:\n  - python=3.10\n  - conda-forge::pandas=2.2\n  - pip:\n    - tqdm==4.66.1\n"
    analysis = analyze({"a.py": b"import scipy, pandas, tqdm\n", "pyproject.toml": pyproject,
                        "environment.yml": conda})
    versions = {d.module: d.version for d in analysis.dependencies}
    assert versions == {"pandas": "==2.2.*", "scipy": "==1.13.0", "tqdm": "==4.66.1"}
    assert analysis.suggested_python == "3.10"


def test_implicit_dependency_from_pandas_read_excel():
    deps = deps_of({"a.py": b"import pandas as pd\npd.read_excel('x.xlsx')\n", "x.xlsx": b""})
    assert deps["openpyxl"].category == "implicit" and deps["openpyxl"].needs_confirmation


def test_declared_but_unused_package_is_reported():
    deps = deps_of({"a.py": b"import numpy\n", "requirements.txt": b"numpy\nmatplotlib\n"})
    assert deps["matplotlib"].category == "declared_only"


def test_removed_stdlib_module_caps_python_version():
    analysis = analyze({"a.py": b"from distutils.version import LooseVersion\n"})
    dep = analysis.dependencies[0]
    assert (dep.category, dep.package) == ("removed", "setuptools")
    assert analysis.suggested_python == "3.11"


def test_messy_project_reports_every_reproducibility_hazard():
    analysis = analyze(read_directory(EXAMPLES / "messy_lab_project"))
    titles = " | ".join(i.title for i in analysis.issues)
    for expected in ("Абсолютный путь", "Динамический импорт", "distutils", "Файл с секретами",
                     "Похоже на секрет", "spectra.xlsx", "seed", "jwt", "labtools_internal", "Версии неизвестны"):
        assert expected in titles, expected
    assert "config.yaml" in analysis.data_found
    assert analysis.entry_candidates[0] == "analysis.py"


def test_local_file_shadowing_stdlib_is_local_with_warning():
    analysis = analyze({"main.py": b"import statistics\n", "statistics.py": b"def mean(x): return 0\n"})
    assert analysis.dependencies[0].category == "local"
    assert any("statistics" in i.title and i.level == "medium" for i in analysis.issues)


def test_python_lower_bound_is_not_pinned_to_minimum_but_new_stdlib_raises_it():
    assert analyze({"a.py": b"import os\n", "pyproject.toml": b'[project]\nrequires-python = ">=3.8"\n'}
                   ).suggested_python == "3.11"
    assert analyze({"a.py": b"import tomllib\n", "environment.yml": b"dependencies:\n  - python=3.9\n"}
                   ).suggested_python == "3.11"


def test_declared_version_found_by_module_name_when_package_name_differs():
    deps = deps_of({"a.py": b"import psycopg2\n", "requirements.txt": b"psycopg2==2.9.9\n"})
    assert deps["psycopg2"].version == "==2.9.9"
    assert "psycopg2" not in {d.module for d in deps.values() if d.category == "declared_only"}


def test_missing_relative_import_target_is_high_issue():
    analysis = analyze({"pkg/__init__.py": b"", "pkg/main.py": b"from .missing import x\n"})
    assert any(i.level == "high" and "missing" in i.title for i in analysis.issues)

def test_declared_alternative_overrides_mapping_default():
    """opencv-python-headless в requirements.txt должен победить справочник."""
    deps = deps_of({"a.py": b"import cv2\n",
                    "requirements.txt": b"opencv-python-headless==4.9.0.80\n"})
    assert deps["cv2"].package == "opencv-python-headless"
    assert deps["cv2"].version == "==4.9.0.80"
    assert not deps["cv2"].needs_confirmation