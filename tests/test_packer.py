import io
import json
import platform
import re
import runpy
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from repropack import packer
from repropack.__main__ import main
from repropack.analysis import analyze
from repropack.intake import read_directory
from repropack.packer import (TREE_LIMIT, PackOptions, Requirement, build_zip, default_requirements, package_tree,
                              render_package, requirements_text, slugify)

EXAMPLES = Path(__file__).parent.parent / "examples"
CI_WORKFLOW = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
# Имя образа для «docker build -t»: строчные латинские буквы и цифры через «-»
DOCKER_NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
FAKE_KEY = "sk-DEMO0000000000000000000000000000fake"


def pack(name: str, **overrides) -> tuple[zipfile.ZipFile, str]:
    analysis = analyze(read_directory(EXAMPLES / name))
    options = PackOptions(**{"project_name": name, "entry_point": analysis.entry_candidates[0],
                             "python_version": analysis.suggested_python,
                             "requirements": default_requirements(analysis), **overrides})
    return zipfile.ZipFile(io.BytesIO(build_zip(analysis, options))), f"{name.replace('_', '-')}-repro"


def test_package_has_all_artifacts_and_original_code():
    archive, root = pack("numpy_pandas_script")
    names = set(archive.namelist())
    for generated in ("README.md", "requirements.txt", "Dockerfile", "REPORT.md", "repro.json",
                      "verify.sh", "verify.ps1"):
        assert f"{root}/{generated}" in names
    assert {f"{root}/project/main.py", f"{root}/project/data/measurements.csv"} <= names
    requirements = archive.read(f"{root}/requirements.txt").decode()
    assert "numpy" in requirements and "pandas" in requirements and "версия неизвестна" in requirements
    readme = archive.read(f"{root}/README.md").decode()
    assert "python main.py" in readme and "project/data/measurements.csv" in readme


def test_secrets_are_excluded_and_redacted_in_package():
    archive, root = pack("messy_lab_project")
    names = archive.namelist()
    assert f"{root}/project/.env" not in names
    code = archive.read(f"{root}/project/analysis.py").decode()
    assert "sk-DEMO" not in code and "<REDACTED>" in code
    blob = b"".join(archive.read(n) for n in names)
    assert b"demo-not-a-real-password" not in blob and b"sk-DEMO0000" not in blob
    template = archive.read(f"{root}/project/.env.example").decode()
    assert "LAB_DB_PASSWORD=\n" in template
    assert "project/.env.example" in archive.read(f"{root}/README.md").decode()


def test_authors_own_env_template_is_kept():
    analysis = analyze({"main.py": b"print(1)\n", ".env": b"A=secret-value\n", ".env.example": b"A=<your key>\n"})
    rendered = zipfile.ZipFile(io.BytesIO(build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))))
    assert rendered.read("p-repro/project/.env.example") == b"A=<your key>\n"


def test_redacted_author_file_keeps_its_encoding():
    source = f"# комментарий\nAPI_KEY = '{FAKE_KEY}'\n".encode("cp1251")
    analysis = analyze({"main.py": source})
    archive = zipfile.ZipFile(io.BytesIO(build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))))
    assert archive.read("p-repro/project/main.py") == source.replace(FAKE_KEY.encode(), b"<REDACTED>")


def test_manifest_lists_issues_and_unconfirmed_requirements():
    archive, root = pack("messy_lab_project")
    manifest = json.loads(archive.read(f"{root}/repro.json"))
    assert manifest["entry_point"] == "analysis.py" and manifest["python"] == "3.11"
    assert any(not r["confirmed"] and r["package"] == "PyJWT" for r in manifest["requirements"])
    assert manifest["excluded_files"] == [".env"]


def test_requirements_text_pins_marks_and_validates():
    text = requirements_text((Requirement("numpy", "1.26.4"), Requirement("pandas", ">=2.0"),
                              Requirement("scipy", ">=1.2,<2"), Requirement("jwt", confirmed=False)), "now")
    assert "numpy==1.26.4" in text and "pandas>=2.0" in text and "scipy>=1.2,<2" in text
    assert "НЕ ПОДТВЕРЖДЕНО" in text
    with pytest.raises(ValueError):
        requirements_text((Requirement("numpy; rm -rf /"),), "now")


@pytest.mark.parametrize("version", ["1.0\n--index-url http://evil", "1.0 --pre", "^1.2", "1.0; os_name=='nt'"])
def test_versions_must_be_pip_specifiers(version):
    with pytest.raises(ValueError, match="версия"):
        requirements_text((Requirement("numpy", version),), "now")


@pytest.mark.parametrize("files", [
    {"pyproject.toml": b'[tool.poetry.dependencies]\nnumpy = "^1.26"\n'},
    {"environment.yml": b"dependencies:\n  - numpy=1.26.4=py311h64a7726_0\n"},
    {"requirements.txt": b"numpy==1.26.4 \\\n    --hash=sha256:abc\n"},
    {"requirements.txt": b"numpy @ https://example.org/numpy.whl\ngit+https://github.com/x/y.git\n"},
])
def test_real_world_dependency_files_do_not_break_the_build(files):
    analysis = analyze({"main.py": b"import numpy\n", **files})
    rendered = render_package(analysis, PackOptions("p", "main.py", "3.11", default_requirements(analysis)))
    assert [line.split("#")[0].strip() for line in rendered["requirements.txt"].splitlines()
            if line.startswith("numpy")] in (["numpy>=1.26,<2"], ["numpy==1.26.4"], ["numpy"])


def test_python_version_is_validated():
    with pytest.raises(ValueError, match="Python"):
        pack("local_module_project", python_version='3.11"; rm -rf ~; "')


def test_run_args_reach_scripts_and_docker():
    archive, root = pack("messy_lab_project", run_args="baseline --verbose")
    assert "analysis.py baseline --verbose" in archive.read(f"{root}/verify.sh").decode()
    assert '["python", "analysis.py", "baseline", "--verbose"]' in archive.read(f"{root}/Dockerfile").decode()


def test_run_args_are_not_expanded_in_verify_scripts(tmp_path: Path):
    archive, root = pack("messy_lab_project", run_args="'$(touch pwned)' \"it's\" ‘x’")
    sh_log = next(line for line in archive.read(f"{root}/verify.sh").decode().splitlines()
                  if line.startswith("log ") and "Запуск" in line)
    result = subprocess.run(["sh", "-c", f'log() {{ printf "%s" "$1"; }}; {sh_log}'],
                            cwd=tmp_path, capture_output=True, text=True, encoding="utf-8", check=True)
    assert "$(touch pwned)" in result.stdout and not (tmp_path / "pwned").exists()
    ps1 = archive.read(f"{root}/verify.ps1").decode()
    assert "& $VPy 'analysis.py' '$(touch pwned)' 'it''s' '‘‘x’’'" in ps1
    assert "Log '-- Запуск:" in ps1


def test_unclosed_quote_in_run_args_is_a_clear_error():
    with pytest.raises(ValueError, match="кавычка"):
        pack("local_module_project", run_args="'unclosed")


def test_unknown_entry_point_is_rejected():
    with pytest.raises(ValueError, match="Точка входа"):
        pack("local_module_project", entry_point="missing.py")


def test_notebook_entry_point_gets_runner_packages():
    nb = json.dumps({"cells": [{"cell_type": "code", "source": "print(1)\n"}]}).encode()
    analysis = analyze({"exp.ipynb": nb})
    rendered = render_package(analysis, PackOptions("p", "exp.ipynb", "3.11", (Requirement("ipykernel"),)))
    assert "nbconvert" in rendered["requirements.txt"] and rendered["requirements.txt"].count("ipykernel") == 1
    assert "--execute exp.ipynb" in rendered["verify.sh"]


def test_docker_installs_system_libraries_of_known_packages():
    archive, root = pack("messy_lab_project")
    dockerfile = archive.read(f"{root}/Dockerfile").decode()
    assert "opencv-python" in dockerfile and "apt-get install -y --no-install-recommends libgl1" in dockerfile
    assert dockerfile.index("apt-get") < dockerfile.index("pip install")
    assert "sudo apt-get install libgl1 libglib2.0-0" in archive.read(f"{root}/README.md").decode()
    archive, root = pack("numpy_pandas_script")
    assert "apt-get" not in archive.read(f"{root}/Dockerfile").decode()


def test_docker_context_skips_local_venv_and_logs():
    archive, root = pack("local_module_project")
    assert ".repro-venv" in archive.read(f"{root}/.dockerignore").decode()


# Подделка интерпретатора: сообщает версию $FAKE, а создать venv не может
FAKE_PYTHON = ('#!/bin/sh\ncase "$1" in\n  --version) echo "Python $FAKE.0" ;;\n  -c) echo "$FAKE" ;;\n'
               '  *) exit 3 ;;\nesac\n')


@pytest.mark.skipif(sys.platform == "win32", reason="нужен POSIX sh")
@pytest.mark.parametrize("found, warned", [("3.9", True), ("3.11", False)])
def test_verify_sh_warns_about_other_python_version_and_keeps_exit_code(tmp_path: Path, found, warned):
    archive, root = pack("local_module_project", python_version="3.11")
    archive.extractall(tmp_path)
    fake = tmp_path / "fake-python"
    fake.write_text(FAKE_PYTHON)
    fake.chmod(0o755)
    result = subprocess.run(["sh", "verify.sh"], cwd=tmp_path / root, capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin", "PYTHON": str(fake), "FAKE": found})
    log = (tmp_path / root / "verify_log.txt").read_text()
    assert result.returncode == 1 and "не удалось создать venv" in log  # подделка не умеет создавать venv
    assert ("ВНИМАНИЕ: нужен Python 3.11, а запускается 3.9" in log) is warned


def test_verify_ps1_matches_verify_sh_checks():
    archive, root = pack("local_module_project", python_version="3.11")
    ps1 = archive.read(f"{root}/verify.ps1").decode("utf-8-sig")
    assert "ВНИМАНИЕ: нужен Python 3.11" in ps1 and "-ne '3.11'" in ps1
    assert "-not (Test-Path $VPy)" in ps1  # без python в PATH скрипт не должен дойти до «exit $null» = 0


def test_cli_builds_package(tmp_path: Path, capsys):
    output = tmp_path / "out.zip"
    assert main([str(EXAMPLES / "messy_lab_project"), "-o", str(output)]) == 0
    assert zipfile.is_zipfile(output)
    out = capsys.readouterr().out
    assert "[критично]" in out and "Итого: 5 критичных" in out and "используются модули, удалённые" in out


def test_cli_version_and_unwritable_output(tmp_path: Path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0 and "repropack 0." in capsys.readouterr().out
    assert main([str(EXAMPLES / "local_module_project"), "-o", str(tmp_path / "no" / "such" / "dir.zip")]) == 1
    assert "не удалось сохранить" in capsys.readouterr().err


def test_cli_reports_errors_with_exit_code(tmp_path: Path, capsys):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    assert main([str(tmp_path / "missing.zip")]) == 1
    assert main([str(tmp_path / "pkg")]) == 1
    assert main([str(EXAMPLES / "local_module_project"), "--entry", "nope.py", "-o", str(tmp_path / "o.zip")]) == 1
    assert capsys.readouterr().err.count("Ошибка") == 3


@pytest.mark.filterwarnings("ignore:.*found in sys.modules:RuntimeWarning")
def test_python_dash_m_runs_the_cli(tmp_path: Path, monkeypatch):
    output = tmp_path / "o.zip"
    monkeypatch.setattr(sys, "argv", ["repropack", str(EXAMPLES / "local_module_project"), "-o", str(output)])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("repropack", run_name="__main__")
    assert exit_info.value.code == 0 and output.exists()


def test_readme_shows_package_structure_with_entry_point_and_data():
    archive, root = pack("numpy_pandas_script")
    readme = archive.read(f"{root}/README.md").decode()
    assert "## Структура пакета" in readme and f"{root}/\n├── .dockerignore" in readme
    tree = readme.split("```text\n", 1)[1].split("```", 1)[0]
    assert "└── project/" in tree and "← код и данные автора" in tree
    assert any(line.startswith("    ├── main.py ") and line.endswith("← точка входа") for line in tree.splitlines())
    assert any(line.startswith("        └── measurements.csv") and line.endswith("← входные данные")
               for line in tree.splitlines())
    assert len({line.index("←") for line in tree.splitlines() if "←" in line}) == 1  # пояснения в одну колонку


def test_tree_of_a_big_project_is_cut_with_a_note():
    lines = package_tree("p-repro", [f"project/m{i:02}.py" for i in range(50)], {}).splitlines()
    assert len(lines) == 1 + TREE_LIMIT + 1 and lines[-1] == "… и ещё 11 — полный состав в архиве"


def test_report_lists_installed_versions_only_with_consent():
    files = {"main.py": b"import jinja2, labtools_internal\n"}

    def rendered(consent: bool) -> dict[str, str]:
        analysis = analyze(files, use_local_env=consent)
        return render_package(analysis, PackOptions("p", "main.py", "3.11", default_requirements(analysis)), "now")

    with_consent = rendered(True)
    section = with_consent["REPORT.md"].split("## Версии установленной среды")[1].split("## Предупреждения")[0]
    assert f"Python {platform.python_version()}" in section and "`Jinja2==" in section
    assert "Версия осталась неизвестной" in section and "labtools_internal" in section
    assert json.loads(with_consent["repro.json"])["local_environment"]["Python"] == platform.python_version()
    without = rendered(False)
    assert "Версии установленной среды" not in without["REPORT.md"]
    assert json.loads(without["repro.json"])["local_environment"] == {}


def test_entry_point_starting_with_dash_is_a_path_not_a_python_option(tmp_path: Path):
    """Аудит: файл «-copen(…)#.py» выполнял код из своего имени (python -c …) вместо самого скрипта."""
    name = "-copen('MARKER','w')#.py"
    analysis = analyze({name: b"print('script body')\n"})
    generated = render_package(analysis, PackOptions("p", name, "3.12", ()))
    assert "'./-copen(" in generated["verify.sh"] and "'./-copen(" in generated["verify.ps1"]
    assert '"./-copen(' in generated["Dockerfile"]
    notebook = render_package(analyze({"-x.ipynb": b'{"cells": []}'}), PackOptions("p", "-x.ipynb", "3.12", ()))
    assert "--execute ./-x.ipynb" in notebook["verify.sh"]


def test_secret_left_after_redaction_stops_the_build(monkeypatch):
    monkeypatch.setattr(packer, "redact_bytes", lambda path, data: data)  # вымарывание «сломалось»
    analysis = analyze({"main.py": f"API_KEY = '{FAKE_KEY}'\n".encode()})
    with pytest.raises(ValueError, match="не удалось заменить"):
        build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))


@pytest.mark.parametrize("python, package, version", [
    ("3.11\n", "numpy", ""), ("３.１１", "numpy", ""), ("3.11", "numpy\n", ""), ("3.11", "numpy", "1.0\n,>=2"),
])
def test_values_must_match_entirely_without_newlines_or_unicode_digits(python, package, version):
    analysis = analyze({"main.py": b"import numpy\n"})
    with pytest.raises(ValueError):
        render_package(analysis, PackOptions("p", "main.py", python, (Requirement(package, version),)))



def test_docker_image_runs_project_as_unprivileged_user():
    """Проект коллеги в контейнере работает не от root: apt-get и pip — от root, затем USER перед CMD."""
    analysis = analyze({"main.py": b"import cv2\n"})
    options = PackOptions("p", "main.py", "3.11", default_requirements(analysis))
    dockerfile = render_package(analysis, options)["Dockerfile"]
    lines = dockerfile.splitlines()
    user = lines.index("USER repro")
    assert "useradd" in dockerfile and "chown repro /app" in dockerfile  # /app — его: код может писать результаты
    assert "COPY --chown=repro:repro project/ ." in lines
    assert lines.index("RUN pip install --no-cache-dir -r requirements.txt") < user
    assert next(i for i, line in enumerate(lines) if "apt-get install" in line) < user
    assert lines[-1].startswith("CMD ") and user < len(lines) - 1



def test_ci_actions_are_pinned_to_commit_sha_and_uv_to_exact_version():
    """Тег действия (actions/checkout@v4) можно перевесить на другой код, а полный SHA коммита — нельзя.

    uv ставится точной версией, токен — только на чтение и не остаётся в .git/config."""
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)", workflow)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action) for action in uses), uses
    assert re.search(r"pip install uv==[0-9]+\.[0-9]+\.[0-9]+\n", workflow)
    assert "\npermissions:\n  contents: read\n" in workflow
    assert workflow.count("persist-credentials: false") == workflow.count("actions/checkout@")



def test_slug_is_unique_for_non_ascii_and_long_names_and_valid_as_docker_image_name():
    """Кириллица и пустое имя не сливаются в «project», длинное имя не даёт папку длиннее 255 байт и тег длиннее 128."""
    names = ["эксперимент", "опыт", "", "Опыт v2", "опыт v2", "x" * 300, "x" * 301, "é" * 300]
    slugs = [slugify(name) for name in names]
    assert len(set(slugs)) == len(names), slugs
    assert all(DOCKER_NAME.fullmatch(slug) and len(slug) <= 64 for slug in slugs), slugs
    assert slugify("numpy_pandas_script") == "numpy-pandas-script" and slugify("My Lab!") == "my-lab"
    assert slugify("эксперимент") == slugify("эксперимент")  # имя архива не меняется от сборки к сборке



def test_comment_ending_with_backslash_does_not_swallow_next_requirement():
    """pip склеивает строку, оканчивающуюся на «\\», со следующей: комментарий «C:\\data\\» съел бы pandas."""
    text = requirements_text((Requirement("numpy", "1.26", comment="данные в C:\\data\\ \\"),
                              Requirement("pandas", ">=2.0")), "now")
    assert not any(line.rstrip().endswith("\\") for line in text.splitlines()), text
    assert "C:\\data" in text and "\npandas>=2.0" in text
