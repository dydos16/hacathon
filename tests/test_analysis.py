from repropack.analysis import _suggest_python, analyze
from repropack.classify import Dependency
from repropack.scanner import FileScan


def needs(version: tuple[int, int]) -> FileScan:
    return FileScan("a.py", (), (), (), frozenset(), version, False)


def test_new_syntax_and_removed_module_conflict_is_reported_not_hidden():
    version, _, issues = _suggest_python([needs((3, 12))], [Dependency("imp", "removed")], "")
    assert version == "3.12"  # на 3.11 код с таким синтаксисом даже не разберётся
    assert [(i.level, "imp" in i.detail, "3.12" in i.detail) for i in issues] == [("high", True, True)]


def test_conflict_with_removed_module_that_has_pypi_replacement_is_not_critical():
    _, _, issues = _suggest_python([needs((3, 12))], [Dependency("distutils", "removed")], "")
    assert [i.level for i in issues] == ["medium"] and "verify.sh" in issues[0].detail


def test_declared_python_that_contradicts_the_code_is_reported():
    pyproject = b'[project]\nrequires-python = "<3.10"\n'
    analysis = analyze({"a.py": b"match x:\n    case 1:\n        pass\n", "pyproject.toml": pyproject})
    assert analysis.suggested_python == "3.10"
    conflict = [i for i in analysis.issues if "расходится" in i.title]
    assert len(conflict) == 1 and conflict[0].level == "medium" and "<3.10" in conflict[0].detail
    removed = analyze({"a.py": b"import imp\n", "pyproject.toml": b'[project]\nrequires-python = ">=3.12"\n'})
    assert removed.suggested_python == "3.11" and any("расходится" in i.title for i in removed.issues)


def test_consistent_python_requirements_raise_no_conflict():
    for files in ({"a.py": b"import os\n", "pyproject.toml": b'[project]\nrequires-python = ">=3.8,<3.11"\n'},
                  {"a.py": b"import imp\n"}, {"a.py": b"type X = int\n"}):
        assert not any("верси" in i.title.lower() and "Python" in i.title for i in analyze(files).issues)


def test_imported_module_is_not_suggested_as_entry_point():
    files = {"model.py": b"def net():\n    pass\n", "train_model.py": b"from model import net\nnet()\n"}
    assert analyze(files).entry_candidates == ("train_model.py", "model.py")


def test_imports_from_tests_do_not_demote_the_main_script():
    files = {"main.py": b"def f():\n    pass\nif __name__ == '__main__':\n    f()\n", "plot.py": b"print(1)\n",
             "tests/test_main.py": b"from main import f\n"}
    assert analyze(files).entry_candidates[0] == "main.py"


def test_tests_setup_and_docs_rank_below_real_scripts():
    guard = b"import unittest\nif __name__ == '__main__':\n    unittest.main()\n"
    files = {"tests/test_a.py": guard, "test_b.py": guard, "b_test.py": guard, "conftest.py": b"import pytest\n",
             "setup.py": b"from setuptools import setup\nsetup()\n", "docs/conf.py": b"project = 'x'\n",
             "process.py": b"print(1)\n"}
    assert analyze(files).entry_candidates[0] == "process.py"
    assert not any(i.title == "Несколько точек входа" for i in analyze(files).issues)


def test_script_reading_command_line_beats_plain_module():
    files = {"a_helpers.py": b"x = 1\n", "z_fit.py": b"import sys\nprint(sys.argv)\n"}
    assert analyze(files).entry_candidates[0] == "z_fit.py"


def test_repeated_issue_from_many_files_is_reported_once():
    files = {f"m{i}.py": b"import random\nrandom.random()\n" for i in range(5)}
    seeds = [i for i in analyze(files).issues if "seed" in i.title]
    assert [i.where for i in seeds] == ["m0.py:2, m1.py:2, m2.py:2 и ещё 2"]


def test_excluded_secret_file_asks_for_a_decision_and_names_the_variables():
    analysis = analyze({"main.py": b"import os\n", ".env": b"# db\nexport DB_PASSWORD=hunter2hunter2\nAPI_TOKEN = x\n",
                        "keys/server.pem": b"-----BEGIN PRIVATE KEY-----\n"})
    issues = {i.where: i for i in analysis.issues if i.title == "Файл с секретами исключён из пакета"}
    assert {i.level for i in issues.values()} == {"medium"}  # исключить — верно; исправлять автору нечего
    assert "DB_PASSWORD, API_TOKEN" in issues[".env"].detail and ".env.example" in issues[".env"].detail
    assert "hunter2" not in issues[".env"].detail and "отдельно" in issues["keys/server.pem"].detail
