"""Сгенерированный Dockerfile на деле: образ собирается, а проект в нём запускается и печатает результат.

Нужны Docker и интернет (базовый образ python:*-slim и пакеты из PyPI), поэтому тесты включаются
переменной REPRO_DOCKER_TESTS=1 — в CI это отдельная задача на Linux.
"""

import io
import os
import shutil
import subprocess
import uuid
import zipfile
from pathlib import Path

import pytest

from repropack.analysis import analyze
from repropack.intake import read_directory
from repropack.packer import PackOptions, build_zip, default_requirements

EXAMPLES = Path(__file__).parent.parent / "examples"
pytestmark = pytest.mark.skipif(not os.environ.get("REPRO_DOCKER_TESTS") or shutil.which("docker") is None,
                                reason="REPRO_DOCKER_TESTS=1 и Docker — собирает образ и ставит пакеты из PyPI")


def docker(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(["docker", *args], cwd=cwd, capture_output=True, text=True, timeout=1200)
    assert result.returncode == 0, f"docker {' '.join(args)}:\n{result.stdout}\n{result.stderr}"
    return result.stdout


def build_and_run(files: dict[str, bytes], tmp_path: Path) -> tuple[str, str]:
    """Собирает пакет, затем образ по его Dockerfile; возвращает (Dockerfile, вывод контейнера)."""
    analysis = analyze(files)
    options = PackOptions("docker-check", analysis.entry_candidates[0], analysis.suggested_python,
                          default_requirements(analysis))
    zipfile.ZipFile(io.BytesIO(build_zip(analysis, options))).extractall(tmp_path)
    package = next(tmp_path.iterdir())
    tag = f"repro-packer-test-{uuid.uuid4().hex[:8]}"
    try:
        docker("build", "-q", "-t", tag, ".", cwd=package)
        return (package / "Dockerfile").read_text(encoding="utf-8"), docker("run", "--rm", tag)
    finally:
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True)


def test_numpy_pandas_demo_runs_in_its_docker_image(tmp_path: Path):
    _, output = build_and_run(read_directory(EXAMPLES / "numpy_pandas_script"), tmp_path)
    assert "solubility =" in output


def test_opencv_gets_the_system_libraries_it_needs_in_slim_image(tmp_path: Path):
    """Без libgl1 в образе python:*-slim «import cv2» падает — строка apt-get в Dockerfile это чинит."""
    dockerfile, output = build_and_run({"main.py": b"import cv2\n\nprint('opencv', cv2.__version__)\n"}, tmp_path)
    assert "apt-get install" in dockerfile and "libgl1" in dockerfile
    assert output.startswith("opencv ")


def test_project_runs_as_unprivileged_user_that_can_write_results(tmp_path: Path):
    """Код коллеги в контейнере работает не от root (uid ≠ 0), но пишет результаты в свою папку /app."""
    script = b"import os\n\nopen('result.txt', 'w').write('ok')\nprint('uid', os.getuid())\n"
    _, output = build_and_run({"main.py": script}, tmp_path)
    assert output.startswith("uid ") and output.split()[1] != "0", output
