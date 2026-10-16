import json
from pathlib import Path

import pytest

from repropack.scanner import scan_notebook, scan_source


def kinds(scan):
    return {ref.module: ref.kind for ref in scan.imports}


def codes(scan):
    return {f.code for f in scan.findings}


def notebook(*sources) -> str:
    return json.dumps({"cells": [{"cell_type": "code", "source": source} for source in sources]})


def test_extracts_static_from_and_relative_imports():
    scan = scan_source("pkg/main.py", "import numpy as np\nfrom pandas import DataFrame\nfrom .utils import f\n")
    assert kinds(scan) == {"numpy": "static", "pandas": "static", "utils": "relative"}
    assert next(r for r in scan.imports if r.kind == "relative").level == 1


def test_marks_try_except_import_error_as_optional_including_fallback():
    source = "try:\n    import ujson as json\nexcept ImportError:\n    import json\n"
    assert kinds(scan_source("a.py", source)) == {"ujson": "optional", "json": "optional"}
    assert kinds(scan_source("a.py", "try:\n    import orjson\nexcept:\n    pass\n")) == {"orjson": "optional"}


def test_imports_after_ordinary_try_and_in_finally_stay_static():
    source = ("try:\n    import numpy\nexcept (KeyError, ValueError):\n    pass\nelse:\n    import scipy\n"
              "finally:\n    import pandas\n")
    assert kinds(scan_source("a.py", source)) == {"numpy": "static", "scipy": "static", "pandas": "static"}


def test_marks_imports_under_if_as_conditional_but_not_under_main_guard():
    source = ("import sys\nif sys.platform == 'win32':\n    import winreg\n"
              "if __name__ == '__main__':\n    import numpy\n")
    scan = scan_source("a.py", source)
    assert kinds(scan)["winreg"] == "conditional"
    assert kinds(scan)["numpy"] == "static"
    assert scan.has_main_guard


def test_dynamic_import_with_literal_is_recorded_and_computed_one_is_flagged():
    source = "import importlib\nimportlib.import_module('scipy.stats')\n__import__(name)\n__import__()\n"
    scan = scan_source("a.py", source)
    assert kinds(scan)["scipy.stats"] == "dynamic"
    assert {"dynamic_import", "dynamic_unresolved"} <= codes(scan)


def test_finds_input_data_but_not_output_files_and_flags_absolute_paths():
    source = ("import pandas as pd\ndf = pd.read_csv('data/in.csv')\ndf.to_csv('out.csv')\n"
              "open('log.txt', 'w')\nopen(file='report.txt', mode='a')\nraw = '/Users/ivan/raw.csv'\n")
    scan = scan_source("a.py", source)
    assert [ref for ref, _ in scan.data_refs] == ["data/in.csv"]
    assert "absolute_path" in codes(scan)


def test_extension_checks_and_fstring_parts_are_not_data_files():
    source = ("import os\ncsvs = [f for f in os.listdir('.') if f.endswith('.csv')]\n"
              "for name in csvs:\n    open(f'data/{name}.csv')\nraw = f'/Users/ivan/{name}.csv'\n"
              "label = f'{len(csvs):>4d} files'\n")
    scan = scan_source("a.py", source)
    assert scan.data_refs == ()
    assert [f.detail for f in scan.findings if f.code == "absolute_path"] == ["f'/Users/ivan/{name}.csv'"]


def test_urls_are_not_local_data_and_cloud_notebook_paths_are_absolute():
    source = ("import pandas as pd\npd.read_csv('https://example.org/d.csv')\n"
              "pd.read_csv('/content/drive/MyDrive/x.csv')\n")
    scan = scan_source("a.py", source)
    assert scan.data_refs == ()
    assert [f.detail for f in scan.findings if f.code == "absolute_path"] == ["/content/drive/MyDrive/x.csv"]


def test_output_paths_built_from_expressions_are_not_inputs():
    source = ("from pathlib import Path\nimport matplotlib.pyplot as plt\nOUT = Path('out')\n"
              "plt.savefig(OUT / 'fig.png')\nPath('summary.txt').write_text('ok')\n"
              "df.to_csv(path_or_buf='table.csv')\nnotes = Path('in.csv').read_text()\n")
    assert [ref for ref, _ in scan_source("a.py", source).data_refs] == ["in.csv"]


def test_unseeded_random_is_flagged_and_seeded_is_not():
    assert "unseeded_random" in codes(scan_source("a.py", "import numpy as np\nnp.random.rand(3)\n"))
    assert "unseeded_random" in codes(scan_source("a.py", "import torch\nx = torch.randn(3)\n"))
    seeded = "import numpy as np\nrng = np.random.default_rng(42)\nrng.normal(size=3)\n"
    assert "unseeded_random" not in codes(scan_source("a.py", seeded))
    torch_seeded = "import torch\ntorch.manual_seed(0)\nx = torch.rand(2)\n"
    assert "unseeded_random" not in codes(scan_source("a.py", torch_seeded))


def test_command_line_arguments_are_noticed():
    assert "cli_args" in codes(scan_source("a.py", "import sys\nprint(sys.argv[1])\n"))
    assert "cli_args" in codes(scan_source("a.py", "import argparse\n"))


def test_min_python_follows_syntax():
    assert scan_source("a.py", "match x:\n    case 1:\n        pass\n").min_python == (3, 10)
    assert scan_source("a.py", "if (n := 1):\n    pass\n").min_python == (3, 8)


def test_syntax_error_is_reported_not_raised():
    scan = scan_source("old.py", "print 'python 2'\n")
    assert codes(scan) == {"syntax_error"} and scan.imports == ()


@pytest.mark.parametrize("source, code", [
    ("import os\x00\n", "syntax_error"),                                    # NUL-байт
    ("x = " + "-" * 100_000 + "1\n", "too_complex"),                        # парсер: MemoryError
    ("x = " + " + ".join(["a"] * 100_000) + "\n", "too_complex"),           # парсер: RecursionError
], ids=["nul-byte", "deep-unary", "long-sum"])
def test_unparsable_sources_are_reported_not_raised(source, code):
    assert codes(scan_source("bad.py", source)) == {code}


def test_huge_generated_formulas_do_not_crash_the_scanner():
    long_sum = "x = " + " + ".join(f"a{i}" for i in range(3000))
    long_chain = "y = obj" + ".attr" * 3000
    scan = scan_source("formula.py", f"import numpy\n{long_sum}\n{long_chain}\n")
    assert [ref.module for ref in scan.imports] == ["numpy"]


def test_notebook_cells_are_scanned_and_pip_magic_collected():
    nb = {"cells": [
        {"cell_type": "markdown", "source": ["import fake_markdown_module"]},
        {"cell_type": "code", "source": ["!pip install seaborn==0.13.2\n", "%matplotlib inline\n", "import seaborn\n"]},
    ]}
    scan = scan_notebook("nb.ipynb", json.dumps(nb))
    assert kinds(scan) == {"seaborn": "static"}
    assert scan.pip_hints == ("seaborn==0.13.2",)


def test_pip_magic_keeps_only_package_requirements():
    scan = scan_notebook("n.ipynb", notebook(
        "!pip install -q -r requirements.txt 'numpy<2' git+https://github.com/x/y.git ./local\n"
        "%pip install seaborn==0.13.2  # графики\n"
        "!python -m pip install --index-url https://example.org/simple scipy\n"
        "!{sys.executable} -m pip install pandas\n!pip3 install xarray\n"
        "!pip install 'unclosed\n"))
    assert scan.pip_hints == ("numpy<2", "seaborn==0.13.2", "scipy", "pandas", "xarray")


def test_notebook_foreign_cell_magics_are_skipped_but_timing_magics_kept():
    scan = scan_notebook("n.ipynb", notebook("%%bash\necho hi\n", "%%time\nimport numpy\n",
                                             "%%writefile helper.py\nimport fake_module\n", "", "%%\n"))
    assert kinds(scan) == {"numpy": "static"} and not codes(scan)


def test_broken_cell_does_not_hide_imports_of_other_cells():
    scan = scan_notebook("n.ipynb", notebook("import pandas\n", "files = !ls\n"))
    assert kinds(scan) == {"pandas": "static"}
    assert [f.detail for f in scan.findings if f.code == "cell_syntax_error"] == ["ячейка 2"]


def test_notebook_locations_name_cell_and_line():
    nb = json.dumps({"cells": [{"cell_type": "markdown", "source": "# Опыт"},
                               {"cell_type": "code", "source": ["x = 1\n", "import scipy\n"]}]})
    scan = scan_notebook("exp.ipynb", nb)
    assert scan.where(scan.imports[0].line) == "exp.ipynb, ячейка 2, стр. 2"
    assert scan.where(0) == "exp.ipynb"
    assert scan_source("a.py", "").where(3) == "a.py:3"


@pytest.mark.parametrize("text", ["not json", "[1, 2]", '{"cells": "x"}', "[" * 100_000 + "]" * 100_000],
                         ids=["not-json", "list", "cells-not-list", "deep-json"])
def test_malformed_notebooks_are_reported_not_raised(text):
    assert codes(scan_notebook("n.ipynb", text)) == {"syntax_error"}


def test_unexpected_cell_shapes_are_ignored():
    nb = json.dumps({"cells": [1, {"cell_type": "code", "source": None},
                               {"cell_type": "code", "source": ["import a\n", 5]}]})
    assert kinds(scan_notebook("n.ipynb", nb)) == {"a": "static"}


def test_scanning_never_executes_code(tmp_path: Path):
    marker = tmp_path / "pwned.txt"
    source = f"open({str(marker)!r}, 'w').write('x')\nimport os\nos.system('echo pwned')\n"
    scan_source("evil.py", source)
    assert not marker.exists()
