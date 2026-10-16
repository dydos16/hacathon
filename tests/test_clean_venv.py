"""Сквозная проверка: собранный пакет ставится и запускается в чистом venv через сгенерированный verify.sh."""

import io
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
needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="нужен POSIX sh")


def run_verify(name: str, tmp_path: Path) -> tuple[subprocess.CompletedProcess, Path]:
    analysis = analyze(read_directory(EXAMPLES / name))
    options = PackOptions(name, analysis.entry_candidates[0], analysis.suggested_python,
                          default_requirements(analysis))
    zipfile.ZipFile(io.BytesIO(build_zip(analysis, options))).extractall(tmp_path)
    package = next(tmp_path.iterdir())
    result = subprocess.run(["sh", "verify.sh"], cwd=package, capture_output=True, text=True, timeout=600,
                            env={**os.environ, "PYTHON": sys.executable})
    return result, package


@needs_sh
def test_local_module_project_runs_in_clean_venv(tmp_path: Path):
    result, package = run_verify("local_module_project", tmp_path)
    log = (package / "verify_log.txt").read_text()
    assert result.returncode == 0, log
    assert "4.666" in log and "РЕЗУЛЬТАТ: OK" in log
    assert (package / "requirements.lock.txt").exists()


@needs_sh
@pytest.mark.network
@pytest.mark.skipif(not os.environ.get("REPRO_NETWORK_TESTS"), reason="REPRO_NETWORK_TESTS=1 — ставит numpy/pandas из PyPI")
def test_numpy_pandas_project_runs_in_clean_venv(tmp_path: Path):
    result, package = run_verify("numpy_pandas_script", tmp_path)
    log = (package / "verify_log.txt").read_text()
    assert result.returncode == 0, log
    assert "solubility =" in log
    lock = (package / "requirements.lock.txt").read_text().lower()
    assert "numpy==" in lock and "pandas==" in lock
