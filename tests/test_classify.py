import json
from importlib import metadata
from pathlib import Path

import pytest

from repropack.analysis import analyze
from repropack.classify import MAPPING_FILE, parse_declared
from repropack.intake import read_directory
from repropack.packer import PACKAGE_NAME, default_requirements

EXAMPLES = Path(__file__).parent.parent / "examples"


def deps_of(files, use_local_env=False):
    return {d.module: d for d in analyze(files, use_local_env).dependencies}


def notebook(*sources) -> bytes:
    return json.dumps({"cells": [{"cell_type": "code", "source": source} for source in sources]}).encode()


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


def test_module_declared_by_author_is_trusted_without_confirmation():
    deps = deps_of({"a.py": b"import labtools\n", "requirements.txt": b"labtools==1.0\n"})
    assert (deps["labtools"].status, deps["labtools"].version, deps["labtools"].needs_confirmation) == (
        "объявлено в проекте", "==1.0", False)


def test_requirement_lines_with_hashes_urls_and_paths_are_parsed_safely():
    requirements = (b"numpy==1.26.4 \\\n    --hash=sha256:abc\nscipy @ https://example.org/scipy.whl\n"
                    b"git+https://github.com/x/y.git#egg=y\n./libs/local_pkg\nlibs/other\n.\n\n"
                    b"pandas >= 2.0 ; python_version < '3.13'\nweird==1.0 (beta)\n")
    deps = deps_of({"a.py": b"import numpy, scipy, pandas\n", "requirements.txt": requirements})
    assert {m: d.version for m, d in deps.items()} == {
        "numpy": "==1.26.4", "pandas": ">= 2.0", "scipy": "", "weird": ""}


def test_pyproject_and_environment_yml_are_read():
    pyproject = b'[project]\nrequires-python = ">=3.10"\ndependencies = ["scipy==1.13.0"]\n'
    conda = b"dependencies:\n  - python=3.10\n  - conda-forge::pandas=2.2\n  - pip:\n    - tqdm==4.66.1\n"
    analysis = analyze({"a.py": b"import scipy, pandas, tqdm\n", "pyproject.toml": pyproject,
                        "environment.yml": conda})
    versions = {d.module: d.version for d in analysis.dependencies}
    assert versions == {"pandas": "==2.2.*", "scipy": "==1.13.0", "tqdm": "==4.66.1"}
    assert analysis.suggested_python == "3.10"


def test_poetry_versions_become_pip_specifiers():
    pyproject = (b'[tool.poetry.dependencies]\npython = "^3.10"\nnumpy = "^1.26"\nscipy = "~1.11.2"\n'
                 b'pandas = {version = "^0.25", optional = true}\nrequests = "2.31.0"\nrich = "*"\n'
                 b'tqdm = "^0.0.3"\nclick = "~8"\nattrs = ">=23.1,<24"\nlocalpkg = {path = "../localpkg"}\n'
                 b'"bad name!" = "1.0"\n')
    deps = deps_of({"a.py": b"import numpy, scipy, pandas, requests, rich, tqdm, click, attrs\n",
                    "pyproject.toml": pyproject})
    assert {m: d.version for m, d in deps.items() if d.category == "external"} == {
        "numpy": ">=1.26,<2", "scipy": ">=1.11.2,<1.12", "pandas": ">=0.25,<0.26", "requests": "==2.31.0",
        "rich": "", "tqdm": ">=0.0.3,<0.0.4", "click": ">=8,<9", "attrs": ">=23.1,<24"}
    assert "bad name!" not in deps and "localpkg" not in deps


@pytest.mark.parametrize("text", [b"[project\n", b"project = 1\ntool = {poetry = 1}\n",
                                  b'[project]\ndependencies = "numpy"\n'])
def test_malformed_pyproject_is_ignored(text):
    assert deps_of({"a.py": b"import os\n", "pyproject.toml": text}) == deps_of({"a.py": b"import os\n"})


def test_conda_export_with_build_strings_and_system_packages():
    env = (b"name: lab\nchannels:\n  - conda-forge\ndependencies:\n"
           b"  - python=3.10.13=hd12c33a_0_cpython\n  - conda-forge::numpy=1.26.4=py310hb13e2d6_0\n"
           b"  - openssl=3.2.1=hd590333_0\n  - libgcc-ng=13.2.0\n  - matplotlib>=3.8  # plots\n"
           b"  - pip:\n    - tqdm==4.66.1\n    - git+https://github.com/x/y.git\n    - -r extra.txt\n"
           b"prefix: /opt/conda/envs/lab\n")
    analysis = analyze({"a.py": b"import numpy, tqdm, matplotlib\n", "environment.yml": env})
    deps = {d.module: d for d in analysis.dependencies}
    assert (deps["numpy"].version, deps["tqdm"].version, deps["matplotlib"].version) == (
        "==1.26.4", "==4.66.1", ">=3.8")
    assert {deps["openssl"].category, deps["libgcc-ng"].category} == {"conda_only"}
    assert "conda-forge" not in deps and "git" not in deps
    assert analysis.suggested_python == "3.10"
    assert any("openssl" in i.detail for i in analysis.issues if i.level == "info")
    assert not any("openssl" in i.title for i in analysis.issues)


def test_conda_list_items_without_indent_and_python_lower_bound():
    env = b"dependencies:\n- python>=3.12\n- numpy=1.26\n- pip:\n  - tqdm\n"
    analysis = analyze({"a.py": b"import numpy, tqdm\n", "environment.yaml": env})
    assert {d.module: d.version for d in analysis.dependencies} == {"numpy": "==1.26.*", "tqdm": ""}
    assert analysis.suggested_python == "3.12"


def test_implicit_dependency_from_pandas_read_excel():
    deps = deps_of({"a.py": b"import pandas as pd\npd.read_excel('x.xlsx')\n", "x.xlsx": b""})
    assert deps["openpyxl"].category == "implicit" and deps["openpyxl"].needs_confirmation


def test_implicit_dependency_requires_pandas_and_is_not_duplicated():
    polars = deps_of({"a.py": b"import polars as pl\npl.read_excel('x.xlsx')\n", "x.xlsx": b""})
    assert "openpyxl" not in polars
    imported = deps_of({"a.py": b"import pandas as pd, openpyxl\npd.read_excel('x.xlsx')\n", "x.xlsx": b""})
    assert imported["openpyxl"].category == "external"


def test_declared_but_unused_package_is_reported():
    deps = deps_of({"a.py": b"import numpy\n", "requirements.txt": b"numpy\nmatplotlib\n"})
    assert deps["matplotlib"].category == "declared_only"


def test_notebook_pip_install_counts_as_declared():
    deps = deps_of({"exp.ipynb": notebook("!pip install seaborn==0.13.2\nimport seaborn\n")})
    assert deps["seaborn"].version == "==0.13.2" and "!pip install" in deps["seaborn"].version_source


def test_local_environment_versions_are_used_only_with_consent():
    files = {"a.py": b"import jinja2, pluggy, sklearn, not_installed_module\n"}
    deps = deps_of(files, use_local_env=True)
    assert deps["jinja2"].version == f"=={metadata.version('Jinja2')}"
    assert deps["jinja2"].version_source == "локальная среда"
    assert (deps["pluggy"].package, deps["pluggy"].status) == ("pluggy", "локальная среда")
    assert deps["sklearn"].version == "" and deps["not_installed_module"].status == "догадка"
    assert deps_of(files)["jinja2"].version == ""


def test_removed_stdlib_module_caps_python_version():
    analysis = analyze({"a.py": b"from distutils.version import LooseVersion\nimport imp\nimport urllib2\n"})
    deps = {d.module: d for d in analysis.dependencies}
    assert (deps["distutils"].category, deps["distutils"].package) == ("removed", "setuptools")
    assert "Python 2" in deps["urllib2"].note and deps["imp"].package == ""
    assert analysis.suggested_python == "3.11"
    assert analysis.python_reason == "используются модули, удалённые в 3.12"


def test_messy_project_reports_every_reproducibility_hazard():
    analysis = analyze(read_directory(EXAMPLES / "messy_lab_project"))
    titles = " | ".join(i.title for i in analysis.issues)
    for expected in ("Абсолютный путь", "Динамический импорт", "distutils", "Файл с секретами",
                     "Похоже на секрет", "spectra\\.xlsx", "seed", "jwt", "labtools_internal", "Версии неизвестны"):
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


@pytest.mark.parametrize("hint, expected", [
    (">=3.8,<3.11", "3.10"), ("<3.10", "3.9"), ("~3.9", "3.9"), ("^3.10", "3.11"),
    ("==3.12.*", "3.12"), ("~=3.12", "3.12"), ("<=3.10", "3.10"), ("*", "3.11"),
])
def test_declared_python_range_is_respected(hint, expected):
    pyproject = f'[project]\nrequires-python = "{hint}"\n'.encode()
    assert analyze({"a.py": b"import os\n", "pyproject.toml": pyproject}).suggested_python == expected


def test_syntax_requirement_wins_over_declared_upper_bound():
    pyproject = b'[project]\nrequires-python = "<3.10"\n'
    source = b"match command:\n    case 'run':\n        pass\n"
    assert analyze({"a.py": source, "pyproject.toml": pyproject}).suggested_python == "3.10"


def test_declared_version_found_by_module_name_when_package_name_differs():
    deps = deps_of({"a.py": b"import psycopg2\n", "requirements.txt": b"psycopg2==2.9.9\n"})
    assert deps["psycopg2"].version == "==2.9.9"
    assert "psycopg2" not in {d.module for d in deps.values() if d.category == "declared_only"}


def test_missing_relative_import_target_is_high_issue():
    analysis = analyze({"pkg/__init__.py": b"", "pkg/main.py": b"from .missing import x\n"})
    assert any(i.level == "high" and "missing" in i.title for i in analysis.issues)


def test_existing_relative_imports_and_conditional_externals():
    files = {"pkg/__init__.py": b"", "pkg/util.py": b"", "pkg/sub/__init__.py": b"",
             "pkg/sub/a.py": (b"from ..util import f\nfrom . import b\nimport sys\n"
                              b"if sys.platform == 'win32':\n    import pywin32_ctypes\n")}
    titles = [i.title for i in analyze(files).issues]
    assert not any("Относительный импорт" in t for t in titles)
    assert "Условный импорт «pywin32_ctypes»" in titles


def test_several_main_guards_are_reported():
    main = b"if __name__ == '__main__':\n    pass\n"
    assert any(i.title == "Несколько точек входа" for i in analyze({"a.py": main, "b.py": main}).issues)


def test_data_found_through_parent_dirs_and_joined_folders():
    files = {"src/main.py": (b"import os\nopen('../data/a.csv')\nopen(os.path.join(DATA, 'b.csv'))\n"
                             b"open('run_%d.csv' % 1)\n"),
             "data/a.csv": b"1", "data/b.csv": b"2"}
    analysis = analyze(files)
    assert analysis.data_found == ("data/a.csv", "data/b.csv") and analysis.data_missing == ()


def test_notebook_issues_and_usages_point_to_cells():
    analysis = analyze({"exp.ipynb": notebook("import numpy as np\nnp.random.rand(3)\n", "files = !ls\n")})
    assert analysis.dependencies[0].locations == ("exp.ipynb, ячейка 1, стр. 1",)
    wheres = {i.title: i.where for i in analysis.issues}
    assert wheres["Случайные числа без фиксированного seed"] == "exp.ipynb, ячейка 1, стр. 2"
    assert wheres["Ячейка ноутбука не разбирается как Python"] == "exp.ipynb"


def packages_of(files) -> list[str]:
    return [r.package for r in default_requirements(analyze(files))]


@pytest.mark.parametrize("module, package, version", [
    ("cv2", "opencv-python-headless", "4.9.0.80"), ("faiss", "faiss-gpu", "1.7.2"), ("psycopg2", "psycopg2", "2.9.9"),
])
def test_declared_variant_of_known_module_replaces_dictionary_default(module, package, version):
    files = {"a.py": f"import {module}\n".encode(), "requirements.txt": f"{package}=={version}\n".encode()}
    dep = deps_of(files)[module]
    assert (dep.package, dep.status, dep.version) == (package, "объявлено в проекте", f"=={version}")
    assert packages_of(files) == [package]


def test_same_package_in_several_files_keeps_the_pinned_version():
    numpy = {"a.py": b"import numpy\n"}
    assert deps_of({**numpy, "environment.yml": b"dependencies:\n  - numpy=1.26.4=py311h_0\n",
                    "requirements.txt": b"numpy\n"})["numpy"].version == "==1.26.4"
    assert deps_of({**numpy, "requirements.txt": b"numpy==1.26.4\n",
                    "pyproject.toml": b'[project]\ndependencies = ["numpy"]\n'})["numpy"].version == "==1.26.4"
    seaborn = deps_of({"exp.ipynb": notebook("!pip install seaborn==0.13.2\nimport seaborn\n"),
                       "requirements.txt": b"seaborn\n"})["seaborn"]
    assert (seaborn.version, seaborn.version_source) == ("==0.13.2", "exp.ipynb (!pip install)")


def test_conflicting_versions_are_reported_and_do_not_depend_on_file_order():
    files = {"sub/requirements.txt": b"numpy==1.24.0\n", "a.py": b"import numpy\n",
             "requirements.txt": b"numpy==1.26.4\n"}
    dep = deps_of(files)["numpy"]
    assert deps_of(dict(reversed(files.items())))["numpy"] == dep
    assert (dep.version, dep.version_source) == ("==1.26.4", "requirements.txt")
    assert dep.note == "версии в файлах расходятся: ==1.26.4 (requirements.txt), ==1.24.0 (sub/requirements.txt)"


def test_package_declared_for_pip_and_conda_is_not_conda_only():
    files = {"a.py": b"import numpy\n", "requirements.txt": b"openpyxl==3.1.2\n",
             "x/environment.yml": b"dependencies:\n  - openpyxl=3.1\n"}
    dep = deps_of(files)["openpyxl"]
    assert (dep.category, dep.version) == ("declared_only", "==3.1.2")
    assert "версии в файлах расходятся" in dep.note and "openpyxl" in packages_of(files)


def test_conda_package_names_are_translated_to_pypi():
    env = b"dependencies:\n  - pytorch=2.1.0\n  - py-opencv=4.8\n  - matplotlib-base=3.8\n  - \"numpy>=1.26\"\n"
    deps = deps_of({"a.py": b"import torch, cv2, matplotlib, numpy\n", "environment.yml": env})
    assert {m: (d.package, d.version) for m, d in deps.items()} == {
        "torch": ("torch", "==2.1.0.*"), "cv2": ("opencv-python", "==4.8.*"),
        "matplotlib": ("matplotlib", "==3.8.*"), "numpy": ("numpy", ">=1.26")}


def test_namespace_packages_are_resolved_by_full_module_path():
    source = (b"from google.protobuf import message\nimport google.cloud.storage\nfrom google.cloud import bigquery\n"
              b"from mpl_toolkits.mplot3d import Axes3D\nfrom mpl_toolkits.basemap import Basemap\n"
              b"from azure.storage.blob import BlobServiceClient\nimport ruamel.yaml\nimport numpy.linalg\n")
    deps = deps_of({"a.py": source})
    assert {m: d.package for m, d in deps.items()} == {
        "google.protobuf": "protobuf", "google.cloud.storage": "google-cloud-storage",
        "google.cloud": "google-cloud-storage", "mpl_toolkits": "matplotlib", "mpl_toolkits.basemap": "basemap",
        "azure.storage.blob": "azure-storage-blob", "ruamel.yaml": "ruamel.yaml", "numpy": "numpy"}
    assert [m for m, d in deps.items() if d.needs_confirmation] == ["google.cloud"]


def test_dotted_distribution_declared_by_author_matches_import():
    files = {"a.py": b"import zope.interface\n", "requirements.txt": b"zope.interface==6.4\n"}
    dep = deps_of(files)["zope.interface"]
    assert (dep.package, dep.version, dep.needs_confirmation) == ("zope.interface", "==6.4", False)
    assert packages_of(files) == ["zope.interface"]


@pytest.mark.parametrize("source, module, hint", [
    (b"from google.colab import drive\n", "google.colab", "Google Colab"),
    (b"import detectron2\n", "detectron2", "GitHub"),
    (b"from apex import amp\n", "apex", "другая библиотека"),
    (b"import matlab.engine\n", "matlab", "MATLAB"),
    (b"from azure.foo import bar\n", "azure", "azure-storage-blob"),
])
def test_modules_not_installable_from_pypi_are_not_guessed(source, module, hint):
    analysis = analyze({"a.py": source})
    dep = next(d for d in analysis.dependencies if d.module == module)
    assert (dep.package, dep.status, dep.needs_confirmation) == ("", "не с PyPI", True)
    assert hint in dep.note and default_requirements(analysis) == ()
    assert any(module in i.title and hint in i.detail for i in analysis.issues)
    assert deps_of({"a.py": source}, use_local_env=True)[module].version == ""


@pytest.mark.parametrize("module, package", [
    ("pywt", "PyWavelets"), ("OpenGL", "PyOpenGL"), ("setuptools", "setuptools"), ("pkg_resources", "setuptools"),
    ("skopt", "scikit-optimize"), ("imblearn", "imbalanced-learn"), ("RPi", "RPi.GPIO"), ("clr", "pythonnet"),
    ("googleapiclient", "google-api-python-client"), ("hydra", "hydra-core"),
])
def test_more_renamed_modules_are_known(module, package):
    dep = deps_of({"a.py": f"import {module}\n".encode()})[module]
    assert (dep.package, dep.needs_confirmation) == (package, False)


@pytest.mark.parametrize("module, first", [("whisper", "openai-whisper"), ("cupy", "cupy-cuda12x")])
def test_modules_shadowed_by_unrelated_pypi_projects_need_confirmation(module, first):
    dep = deps_of({"a.py": f"import {module}\n".encode()})[module]
    assert dep.needs_confirmation and dep.candidates[0] == first


def test_mapping_file_contains_only_valid_package_names():
    data = json.loads(MAPPING_FILE.read_text(encoding="utf-8"))
    names = [*data["known"].values(), *data["conda_to_pypi"].values(),
             *(n for section in ("ambiguous", "alternatives") for names in data[section].values() for n in names)]
    assert all(PACKAGE_NAME.match(n) for n in names)
    sections = [set(data[s]) for s in ("known", "ambiguous", "not_on_pypi")]
    assert sum(map(len, sections)) == len(set().union(*sections))


def test_setup_py_setup_cfg_and_pipfile_are_read_statically():
    setup_py = (b"from setuptools import setup\nsetup(name='x', python_requires='>=3.10',\n"
                b"      install_requires=['numpy==1.26.4', 'scipy>=1.11'])\n")
    setup_cfg = b"[options]\npython_requires = >=3.9\ninstall_requires =\n    pandas==2.2.0\n    file: req.txt\n"
    pipfile = (b'[packages]\ntqdm = "==4.66.1"\nrich = "*"\nclick = {version = ">=8.1", extras = ["x"]}\n'
               b'lib = {git = "https://github.com/x/lib.git"}\n[requires]\npython_version = "3.10"\n')
    deps, python = parse_declared({"setup.py": setup_py, "pkg/setup.cfg": setup_cfg, "Pipfile": pipfile})
    assert {n: d.spec for n, d in deps.items()} == {
        "numpy": "==1.26.4", "scipy": ">=1.11", "pandas": "==2.2.0", "tqdm": "==4.66.1", "rich": "",
        "click": ">=8.1"}
    assert python == "3.10"
    assert parse_declared({"setup.py": setup_py, "pkg/setup.cfg": setup_cfg})[1] == ">=3.9"


@pytest.mark.parametrize("name, text", [
    ("setup.py", b"from setuptools import setup\nsetup(install_requires=REQUIREMENTS)\n"),
    ("setup.py", b"setup(install_requires=['numpy'] + extra)\n"),
    ("setup.py", b"def broken(:\n"),
    ("setup.py", b"x = " + b"(" * 300 + b")" * 300 + b"\n"),
    ("setup.py", b"setup(name=1, python_requires=3)\nother(install_requires=['numpy'])\n"),
    ("setup.py", b"import setuptools\nsetuptools.setup(**CONFIG)\n"),
    ("setup.py", b"print('setup is elsewhere')\n"),
    ("setup.cfg", b"[options\ninstall_requires = numpy\n"),
    ("setup.cfg", b"[metadata]\nname = x\n"),
    ("Pipfile", b"[packages\n"),
])
def test_unreadable_declarations_are_ignored(name, text):
    assert parse_declared({name: text}) == ({}, "")


def test_requirements_saved_by_windows_tools_are_read():
    text = "numpy==1.26.4\r\npandas==2.2.0\r\n"
    for data in (b"\xef\xbb\xbf" + text.encode(), text.encode("utf-16")):
        assert {n: d.spec for n, d in parse_declared({"requirements.txt": data})[0].items()} == {
            "numpy": "==1.26.4", "pandas": "==2.2.0"}
