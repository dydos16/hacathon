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


@pytest.mark.parametrize("path", ["keys/server.jks", "deploy/prod.tfvars", "keys/signing.p8", "vault/key.ppk"])
def test_keystores_and_infra_variables_are_secret_files(path):
    """Пункт 5: эти файлы почти всегда содержат пароли и ключи и не должны уходить в пакет."""
    from repropack.secrets import is_secret_file

    assert is_secret_file(path), path


def test_docker_context_leaves_secret_files_out_but_keeps_env_templates():
    """Пункт 5: COPY project/ копирует всё из контекста сборки — секретные файлы туда попадать не должны."""
    from repropack.packer import DOCKERIGNORE

    lines = DOCKERIGNORE.splitlines()
    for pattern in ("**/.env*", "**/*.pem", "**/*.key", "**/*.jks", "**/*.tfvars", "**/.aws/", "**/.ssh/", "**/.docker/"):
        assert pattern in lines, pattern
    assert "!**/.env.example" in lines
    assert lines.index("!**/.env.example") > lines.index("**/.env*")  # в .dockerignore побеждает последнее правило


def test_huge_version_number_in_poetry_does_not_break_analysis():
    """Пункт 6: длинное число в версии Poetry роняло весь анализ: int() не принимает строку длиннее 4300 цифр."""
    huge = "^" + "1" * 5000
    analysis = analyze({"main.py": b"import numpy\n",
                        "pyproject.toml": f'[tool.poetry.dependencies]\nnumpy = "{huge}"\n'.encode()})
    assert any(d.module == "numpy" for d in analysis.dependencies)


def test_declared_file_that_cannot_be_read_becomes_an_issue_not_a_crash(monkeypatch):
    """Пункт 6: один нечитаемый файл зависимостей не должен валить анализ всего проекта."""
    from repropack import classify

    def broken(text, source):
        raise ValueError("некорректная запись")

    monkeypatch.setitem(classify.READERS, "pyproject.toml", (broken, False))
    analysis = analyze({"main.py": b"import os\n", "pyproject.toml": b"[project]\n"})
    assert any(i.title == "Файл «pyproject\\.toml» не разобран" and i.level == "medium" for i in analysis.issues)


def test_oversized_setup_py_is_refused_before_ast_parse():
    """Пункт 7: setup.py на мегабайты разбирался ast без лимита: память росла примерно на 120 МБ на мегабайт."""
    from repropack import classify
    from repropack.scanner import MAX_CODE_CHARS

    big = "setup(install_requires=[" + ",".join(f"'p{i}'" for i in range(MAX_CODE_CHARS // 4)) + "])\n"
    with pytest.raises(ValueError, match="слишком большой"):
        classify._from_setup_py(big, "setup.py")


def test_long_dotted_import_line_is_skipped_as_long_statement():
    """Пункт 7: одна строка с 20 000 частей имени занимала память и время квадратично, а теперь пропускается."""
    from repropack.scanner import scan_source

    scan = scan_source("a.py", "import " + ".".join(["a"] * 20_000) + "\n")
    assert [f.code for f in scan.findings] == ["long_statement"]
    assert scan.imports == ()


def test_long_string_literal_is_still_parsed_normally():
    """Длинная строка-данные — одна лексема, её не нужно пропускать: импорты рядом должны находиться."""
    from repropack.scanner import scan_source

    scan = scan_source("a.py", "x = '" + "a" * 5000 + "'\nimport os\n")
    assert scan.findings == () and [ref.module for ref in scan.imports] == ["os"]


def test_multiline_formula_that_overflows_the_parser_is_skipped():
    """Пункт 7: формула на сотнях тысяч коротких строк не длинная по символам, но парсер на ней падает — пропускаем её."""
    from repropack.scanner import scan_source

    formula = "x = (\n" + " +\n".join(["a"] * 100_000) + ")\n"
    scan = scan_source("f.py", "import numpy\n" + formula)
    assert [f.code for f in scan.findings] == ["long_statement"]
    assert [ref.module for ref in scan.imports] == ["numpy"]


def test_expression_text_falls_back_when_unparse_overflows(monkeypatch):
    """Глубокое выражение не должно валить отчёт при печати его текста: вместо текста — пометка."""
    import ast

    from repropack import scanner

    def overflow(node):
        raise RecursionError

    monkeypatch.setattr(scanner.ast, "unparse", overflow)
    assert scanner._source(ast.parse("a", mode="eval").body) == "(слишком глубокое выражение)"


def test_unreadable_declared_file_path_cannot_become_a_link_in_the_report():
    """Путь файла зависимостей — текст пользователя: в заголовке проблемы он не должен стать ссылкой."""
    from repropack.markdown import escape

    path = "a[b](http:evil)/requirements.txt"
    analysis = analyze({"main.py": b"import os\n", path: b"numpy\n" + b"#" * (2 * 1024 * 1024) + b"\n"})
    assert f"Файл «{escape(path)}» не разобран" in [i.title for i in analysis.issues]
