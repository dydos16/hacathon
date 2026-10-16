"""Исправления по аудиту безопасности: каждый тест падает до исправления и говорит, что именно проверяет."""

import io
import zipfile
from pathlib import Path

import pytest

from repropack import intake
from repropack.analysis import analyze
from repropack.intake import IntakeError, read_upload
from repropack.packer import PackOptions, render_package

ROOT = Path(__file__).parent.parent
LOOPBACK_COMMAND = "streamlit run app.py --server.address 127.0.0.1"


def test_local_run_command_listens_on_loopback_only_in_readme_and_demo():
    """Пункт 1: без адреса Streamlit слушает всю локальную сеть, и чужие люди видят сервис."""
    for doc in ("README.md", "DEMO.md"):
        assert LOOPBACK_COMMAND in (ROOT / doc).read_text(encoding="utf-8"), doc


def test_security_promise_says_it_holds_only_for_local_runs():
    """Пункт 2: «секреты не покидают машину» верно только для локального запуска."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    promise = next(line for line in text.splitlines() if "не покидают машину" in line.lower())
    assert "при локальном запуске" in promise.lower()
    assert "общем сервере" in promise


def test_windows_run_command_is_powershell_and_warns_about_cmd():
    """Пункт 4: в cmd.exe символ & в имени файла запускает вторую команду, поэтому Windows-команда отдельная."""
    analysis = analyze({"g&h.py": b"import sys\nprint(sys.argv)\n"})
    options = PackOptions("p", "g&h.py", "3.11", (), "--name a&calc")
    readme = render_package(analysis, options, "now")["README.md"]
    assert "```powershell" in readme
    assert "python 'g&h.py' '--name' 'a&calc'" in readme
    assert "cmd.exe" in readme and "не вставляйте" in readme.lower()


def zip_with(method: int, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(zipfile.ZipInfo("main.py"), data, compress_type=method)
    return buffer.getvalue()


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_archives_with_rare_compression_methods_are_rejected(method):
    """Пункт 3: bzip2 и lzma сжимают нули в тысячи раз и обходят проверку заявленного размера."""
    with pytest.raises(IntakeError, match="неподдерживаемым методом"):
        read_upload([("p.zip", zip_with(method, b"print(1)\n"))])


def test_stored_and_deflated_archives_are_still_read():
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        assert read_upload([("p.zip", zip_with(method, b"print(1)\n"))]) == {"main.py": b"print(1)\n"}


def test_unpacked_size_is_counted_by_real_bytes_not_by_header():
    """Пункт 3: заголовок может соврать о размере, поэтому лимит считается по реально прочитанным байтам."""
    with pytest.raises(IntakeError, match="zip-бомба"):
        intake._read_limited(io.BytesIO(b"x" * 5000), 1000)
    assert intake._read_limited(io.BytesIO(b"x" * 500), 1000) == b"x" * 500
