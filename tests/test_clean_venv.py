"""Сквозная проверка: собранный пакет ставится и запускается в чистом venv через сгенерированный verify-скрипт.

Linux/macOS — verify.sh, Windows — verify.ps1 (Windows PowerShell, как написано в README пакета).
"""

import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from repropack.analysis import analyze
from repropack.intake import read_directory
from repropack.packer import PackOptions, build_zip, default_requirements

EXAMPLES = Path(__file__).parent.parent / "examples"
WINDOWS = sys.platform == "win32"
VERIFY = (["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "verify.ps1"] if WINDOWS
          else ["sh", "verify.sh"])
needs_shell = pytest.mark.skipif(shutil.which(VERIFY[0]) is None, reason=f"нужен {VERIFY[0]}")
needs_network = pytest.mark.skipif(not os.environ.get("REPRO_NETWORK_TESTS"),
                                   reason="REPRO_NETWORK_TESTS=1 — ставит numpy/pandas из PyPI")
NOTEBOOK = json.dumps({
    "cells": [{"cell_type": "code", "metadata": {}, "outputs": [], "execution_count": None,
               "source": ["import statistics\n", "print('mean =', statistics.mean([1, 2, 3]))\n"]}],
    "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"}},
    "nbformat": 4, "nbformat_minor": 5}).encode()


def run_verify(files: dict[str, bytes], tmp_path: Path,
               run_args: str = "") -> tuple[subprocess.CompletedProcess, Path, str]:
    analysis = analyze(files)
    options = PackOptions("project", analysis.entry_candidates[0], analysis.suggested_python,
                          default_requirements(analysis), run_args)
    zipfile.ZipFile(io.BytesIO(build_zip(analysis, options))).extractall(tmp_path)
    package = next(tmp_path.iterdir())
    result = subprocess.run(VERIFY, cwd=package, capture_output=True, timeout=900,
                            env={**os.environ, "PYTHON": sys.executable})
    # Лог читается так, как его откроет коллега: обычный UTF-8 (BOM допустим)
    log = (package / "verify_log.txt").read_text(encoding="utf-8-sig")
    return result, package, log


@needs_shell
def test_local_module_project_runs_in_clean_venv(tmp_path: Path):
    result, package, log = run_verify(read_directory(EXAMPLES / "local_module_project"), tmp_path)
    assert result.returncode == 0, log
    assert "4.666" in log and "РЕЗУЛЬТАТ: OK" in log
    assert (package / "requirements.lock.txt").exists()


@needs_shell
def test_cyrillic_output_and_args_survive_verify_script(tmp_path: Path):
    files = {"main.py": "import sys\n\nif __name__ == '__main__':\n    print('Привет,', sys.argv[1:])\n".encode()}
    result, _, log = run_verify(files, tmp_path, run_args="мир 'два слова'")
    assert result.returncode == 0, log
    assert "Привет, ['мир', 'два слова']" in log and "РЕЗУЛЬТАТ: OK" in log


@needs_shell
@needs_network
@pytest.mark.network
def test_numpy_pandas_project_runs_in_clean_venv(tmp_path: Path):
    result, package, log = run_verify(read_directory(EXAMPLES / "numpy_pandas_script"), tmp_path)
    assert result.returncode == 0, log
    assert "solubility =" in log
    lock = (package / "requirements.lock.txt").read_text(encoding="utf-8-sig").lower()
    assert "numpy==" in lock and "pandas==" in lock


@needs_shell
@needs_network
@pytest.mark.network
def test_messy_project_fails_honestly_with_the_reason_in_the_log(tmp_path: Path):
    """Шаг 9 демо: воспроизвести нельзя — скрипт не зависает и не молчит, а называет причину.
    Неподтверждённые пакеты закомментированы в requirements.txt, поэтому установка проходит, а запуск падает
    на импорте пакета, которого в окружении нет."""
    result, package, log = run_verify(read_directory(EXAMPLES / "messy_lab_project"), tmp_path)
    assert result.returncode == 1, log
    assert "РЕЗУЛЬТАТ: ОШИБКА запуска" in log
    assert "ModuleNotFoundError" in log
    assert not (package / "project" / "executed.ipynb").exists()


@needs_shell
@needs_network
@pytest.mark.network
def test_notebook_is_executed_end_to_end_in_clean_venv(tmp_path: Path):
    """Ноутбук — точка входа: verify-скрипт ставит nbconvert и ipykernel и выполняет ячейки."""
    result, package, log = run_verify({"experiment.ipynb": NOTEBOOK}, tmp_path)
    assert result.returncode == 0, log
    assert "РЕЗУЛЬТАТ: OK" in log
    executed = json.loads((package / "project" / "executed.ipynb").read_text(encoding="utf-8"))
    printed = "".join("".join(out.get("text", "")) for cell in executed["cells"] for out in cell.get("outputs", []))
    assert "mean = 2" in printed
    lock = (package / "requirements.lock.txt").read_text(encoding="utf-8-sig").lower()
    assert "nbconvert==" in lock and "ipykernel==" in lock
