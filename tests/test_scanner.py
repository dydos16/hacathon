import json
from pathlib import Path

from repropack.scanner import scan_notebook, scan_source


def kinds(scan):
    return {ref.module: ref.kind for ref in scan.imports}


def codes(scan):
    return {f.code for f in scan.findings}


def test_extracts_static_from_and_relative_imports():
    scan = scan_source("pkg/main.py", "import numpy as np\nfrom pandas import DataFrame\nfrom .utils import f\n")
    assert kinds(scan) == {"numpy": "static", "pandas": "static", "utils": "relative"}
    assert next(r for r in scan.imports if r.kind == "relative").level == 1


def test_marks_try_except_import_error_as_optional_including_fallback():
    source = "try:\n    import ujson as json\nexcept ImportError:\n    import json\n"
    assert kinds(scan_source("a.py", source)) == {"ujson": "optional", "json": "optional"}


def test_marks_imports_under_if_as_conditional_but_not_under_main_guard():
    source = ("import sys\nif sys.platform == 'win32':\n    import winreg\n"
              "if __name__ == '__main__':\n    import numpy\n")
    scan = scan_source("a.py", source)
    assert kinds(scan)["winreg"] == "conditional"
    assert kinds(scan)["numpy"] == "static"
    assert scan.has_main_guard


def test_dynamic_import_with_literal_is_recorded_and_computed_one_is_flagged():
    source = "import importlib\nimportlib.import_module('scipy.stats')\n__import__(name)\n"
    scan = scan_source("a.py", source)
    assert kinds(scan)["scipy.stats"] == "dynamic"
    assert {"dynamic_import", "dynamic_unresolved"} <= codes(scan)


def test_finds_input_data_but_not_output_files_and_flags_absolute_paths():
    source = ("import pandas as pd\ndf = pd.read_csv('data/in.csv')\ndf.to_csv('out.csv')\n"
              "open('log.txt', 'w')\nraw = '/Users/ivan/raw.csv'\n")
    scan = scan_source("a.py", source)
    assert [ref for ref, _ in scan.data_refs] == ["data/in.csv"]
    assert "absolute_path" in codes(scan)


def test_unseeded_random_is_flagged_and_seeded_is_not():
    assert "unseeded_random" in codes(scan_source("a.py", "import numpy as np\nnp.random.rand(3)\n"))
    seeded = "import numpy as np\nrng = np.random.default_rng(42)\nrng.normal(size=3)\n"
    assert "unseeded_random" not in codes(scan_source("a.py", seeded))


def test_min_python_follows_syntax():
    assert scan_source("a.py", "match x:\n    case 1:\n        pass\n").min_python == (3, 10)
    assert scan_source("a.py", "if (n := 1):\n    pass\n").min_python == (3, 8)


def test_syntax_error_is_reported_not_raised():
    scan = scan_source("old.py", "print 'python 2'\n")
    assert codes(scan) == {"syntax_error"} and scan.imports == ()


def test_notebook_cells_are_scanned_and_pip_magic_collected():
    notebook = {"cells": [
        {"cell_type": "markdown", "source": ["import fake_markdown_module"]},
        {"cell_type": "code", "source": ["!pip install seaborn==0.13.2\n", "%matplotlib inline\n", "import seaborn\n"]},
    ]}
    scan = scan_notebook("nb.ipynb", json.dumps(notebook))
    assert kinds(scan) == {"seaborn": "static"}
    assert scan.pip_hints == ("seaborn==0.13.2",)


def test_scanning_never_executes_code(tmp_path: Path):
    marker = tmp_path / "pwned.txt"
    source = f"open({str(marker)!r}, 'w').write('x')\nimport os\nos.system('echo pwned')\n"
    scan_source("evil.py", source)
    assert not marker.exists()

def test_default_rng_without_seed_is_flagged():
    src = "import numpy as np\nnp.random.default_rng().normal(size=3)\n"
    assert "unseeded_random" in codes(scan_source("a.py", src))


def test_default_rng_with_seed_is_not_flagged():
    src = "import numpy as np\nnp.random.default_rng(42).normal(size=3)\n"
    assert "unseeded_random" not in codes(scan_source("a.py", src))
