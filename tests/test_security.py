"""Регрессионные тесты по аудиту безопасности: то, что пропускалось и после коммита 487f61d."""

import codecs
import io
import sys
import time
import tomllib
import zipfile
from pathlib import Path

import pytest

from repropack import intake
from repropack.analysis import analyze
from repropack.intake import IntakeError, read_directory, read_upload
from repropack.markdown import code, escape
from repropack.packer import (PackOptions, Requirement, build_zip, default_requirements, render_package,
                              requirements_text, run_parts)
from repropack.secrets import env_names, file_text, find_secrets, is_secret_file, redact_bytes

ROOT = Path(__file__).parent.parent
EXAMPLES = ROOT / "examples"
FAKE_KEY = "sk-DEMO0000000000000000000000000000fake"


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def pack(name: str, **overrides) -> tuple[zipfile.ZipFile, str]:
    analysis = analyze(read_directory(EXAMPLES / name))
    options = PackOptions(**{"project_name": name, "entry_point": analysis.entry_candidates[0],
                             "python_version": analysis.suggested_python,
                             "requirements": default_requirements(analysis), **overrides})
    return zipfile.ZipFile(io.BytesIO(build_zip(analysis, options))), f"{name.replace('_', '-')}-repro"


# --- загрузка: архивы, ссылки и имена ---

@pytest.mark.skipif(sys.platform == "win32", reason="символические ссылки в Windows требуют прав администратора")
def test_directory_does_not_follow_links_outside_the_project(tmp_path: Path):
    secret = tmp_path / "home" / "credentials"
    secret.parent.mkdir()
    secret.write_text("aws_secret = not-a-real-key")
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text("print(1)")
    (project / "notes.py").symlink_to(secret)
    (project / "linked").symlink_to(secret.parent)
    assert read_directory(project) == {"main.py": b"print(1)"}


def test_colon_in_any_path_part_is_rejected():
    with pytest.raises(IntakeError, match="Небезопасный путь"):
        read_upload([("p.zip", make_zip({"main.py": b"", "dir/x:stream.py": b""}))])


def test_invisible_format_characters_in_names_are_rejected():
    with pytest.raises(IntakeError, match="символ"):
        read_upload([("p.zip", make_zip({"ma‮in.py": b"x = 1"}))])


def test_duplicate_names_inside_one_zip_are_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("main.py", b"old")
        archive.writestr("main.py", b"new")
    with pytest.raises(IntakeError, match="несколько"):
        read_upload([("p.zip", buffer.getvalue())])


def test_names_differing_only_by_case_are_rejected():
    with pytest.raises(IntakeError, match="регистр"):
        read_upload([("p.zip", make_zip({"Main.py": b"a", "main.py": b"b"}))])
    with pytest.raises(IntakeError, match="регистр"):
        read_upload([("Main.py", b"a"), ("main.py", b"b")])


def test_zip_record_count_is_checked_before_parsing(monkeypatch):
    monkeypatch.setattr(intake, "MAX_ZIP_RECORDS", 2)
    with pytest.raises(IntakeError, match="записей"):
        read_upload([("p.zip", make_zip({"main.py": b"", "a.py": b"", "b.py": b""}))])


# --- секреты ---

@pytest.mark.parametrize("path", ["id_rsa.bak", "keys/AuthKey_X.p8", "store/keystore.JKS", "terraform.tfvars",
                                  ".npmrc", ".envrc", ".ENV", "credentials.json.old", "app.ppk"])
def test_key_and_credential_files_under_other_names_are_secret(path):
    assert is_secret_file(path)


def test_unquoted_secret_in_env_template_is_found_and_redacted_only_there():
    line = "DB_PASSWORD=Sup3rS3cretPW9\n"
    assert len(find_secrets(".env.example", line)) == 1
    assert find_secrets("main.py", line) == []
    assert redact_bytes(".env.example", line.encode()) == b"DB_PASSWORD=<REDACTED>\n"


def test_percent_encoded_password_in_url_is_found_but_placeholders_are_not():
    assert find_secrets("a.py", 'dsn = "postgresql://app:Sup%40rS3cret@db/x"')
    assert find_secrets("a.py", 'dsn = "postgresql://app:%(pw)s@db/x"') == []


def test_long_line_of_dotted_words_is_scanned_in_linear_time():
    started = time.perf_counter()
    assert find_secrets("a.txt", "a." * 50_000) == []
    assert time.perf_counter() - started < 2


def test_utf16_files_are_scanned_and_redacted_keeping_the_encoding():
    text = 'password = "hunter2hunter2"\n'
    data = codecs.BOM_UTF16_LE + text.encode("utf-16-le")
    assert find_secrets("config.json", file_text(data)[0])
    cleaned = redact_bytes("config.json", data)
    assert cleaned.startswith(codecs.BOM_UTF16_LE) and "hunter2" not in cleaned.decode("utf-16-le")


def test_long_secret_is_fully_hidden_in_the_mask():
    [hit] = find_secrets("a.py", f'api_key = "{"x" * 25}"\n')
    assert hit.masked == "…"


def test_env_names_skip_private_key_bodies():
    text = 'KEY="-----BEGIN PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD==\n-----END PRIVATE KEY-----"\nOTHER=1\n'
    assert env_names(".env", text) == ["KEY", "OTHER"]


# --- пакет: requirements, команды, Markdown ---

def test_unconfirmed_requirement_is_commented_out():
    text = requirements_text((Requirement("jwt", confirmed=False), Requirement("numpy", "1.26.4")), "now")
    installable = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    assert installable == ["numpy==1.26.4"]


def test_python_version_must_be_exactly_major_minor():
    with pytest.raises(ValueError, match="Python"):
        pack("local_module_project", python_version="3.11\n")


def test_entry_point_named_like_an_option_is_run_as_a_path():
    assert run_parts("-evil.py", "") == ["./-evil.py"]
    assert "./-evil.ipynb" in run_parts("-evil.ipynb", "")


def test_secret_in_run_args_is_not_echoed_into_readme_or_manifest():
    # build_zip с ключом в аргументах пакет не собирает (test_secrets); здесь — текст README и repro.json
    analysis = analyze({"main.py": b"print(1)\n"})
    generated = render_package(analysis, PackOptions("p", "main.py", "3.11", (), f"--key {FAKE_KEY}"))
    assert FAKE_KEY not in generated["README.md"]
    assert FAKE_KEY not in generated["repro.json"]


def test_windows_instructions_do_not_disable_the_execution_policy():
    archive, root = pack("local_module_project")
    readme = archive.read(f"{root}/README.md").decode()
    assert "Bypass" not in readme and "Unblock-File" in readme


def test_user_text_in_report_is_escaped_as_markdown():
    files = {"main.py": b'PATH = "/srv/*lab*/data.csv"\nprint(PATH)\n'}
    analysis = analyze(files)
    options = PackOptions("p", "main.py", "3.11", default_requirements(analysis))
    assert "\\*lab\\*" in render_package(analysis, options)["REPORT.md"]


def test_markdown_specials_in_text_are_escaped():
    assert escape("data*[1]_v2.csv") == "data\\*\\[1\\]\\_v2\\.csv"


def test_plain_names_stay_readable_inside_code_spans():
    assert code("analysis.py") == "`analysis.py`"


def test_backticks_cannot_break_out_of_a_code_span():
    assert code("a`b") == "``a`b``"
    assert code("`x") == "`` `x ``"


# --- развёртывание ---

def test_error_details_are_not_shown_to_visitors():
    config = tomllib.loads((ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    assert config["client"]["showErrorDetails"] == "none"


def test_ci_workflow_grants_read_only_token():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "\npermissions:\n  contents: read\n" in workflow


def test_pandas_used_by_the_app_is_declared():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert any(dep.startswith("pandas") for dep in pyproject["project"]["dependencies"])
