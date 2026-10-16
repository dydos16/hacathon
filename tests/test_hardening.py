"""Исправления по аудиту безопасности: каждый тест падает до исправления и говорит, что именно проверяет."""

from pathlib import Path

from repropack.analysis import analyze
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
