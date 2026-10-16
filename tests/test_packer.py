import io
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from repropack.__main__ import main
from repropack.analysis import analyze
from repropack.intake import read_directory
from repropack.packer import PackOptions, Requirement, build_zip, default_requirements, requirements_text

EXAMPLES = Path(__file__).parent.parent / "examples"


def pack(name: str, **overrides) -> tuple[zipfile.ZipFile, str]:
    analysis = analyze(read_directory(EXAMPLES / name))
    options = PackOptions(project_name=name, entry_point=analysis.entry_candidates[0],
                          python_version=analysis.suggested_python,
                          requirements=default_requirements(analysis), **overrides)
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


def test_manifest_lists_issues_and_unconfirmed_requirements():
    archive, root = pack("messy_lab_project")
    manifest = json.loads(archive.read(f"{root}/repro.json"))
    assert manifest["entry_point"] == "analysis.py" and manifest["python"] == "3.11"
    assert any(not r["confirmed"] and r["package"] == "PyJWT" for r in manifest["requirements"])
    assert manifest["excluded_files"] == [".env"]


def test_requirements_text_pins_marks_and_validates():
    text = requirements_text((Requirement("numpy", "1.26.4"), Requirement("pandas", ">=2.0"),
                              Requirement("jwt", confirmed=False)), "now")
    assert "numpy==1.26.4" in text and "pandas>=2.0" in text and "НЕ ПОДТВЕРЖДЕНО" in text
    with pytest.raises(ValueError):
        requirements_text((Requirement("numpy; rm -rf /"),), "now")
    with pytest.raises(ValueError):
        requirements_text((Requirement("numpy", "1.0\n--index-url http://evil"),), "now")


def test_run_args_reach_scripts_and_docker():
    archive, root = pack("messy_lab_project", run_args="baseline --verbose")
    assert "analysis.py baseline --verbose" in archive.read(f"{root}/verify.sh").decode()
    assert '["python", "analysis.py", "baseline", "--verbose"]' in archive.read(f"{root}/Dockerfile").decode()


def test_run_args_are_not_expanded_in_verify_scripts(tmp_path: Path):
    archive, root = pack("messy_lab_project", run_args="'$(touch pwned)' \"it's\" ‘x’")
    sh_log = next(line for line in archive.read(f"{root}/verify.sh").decode().splitlines()
                  if line.startswith("log ") and "Запуск" in line)
    result = subprocess.run(["sh", "-c", f'log() {{ printf "%s" "$1"; }}; {sh_log}'],
                            cwd=tmp_path, capture_output=True, text=True, check=True)
    assert "$(touch pwned)" in result.stdout and not (tmp_path / "pwned").exists()
    ps1 = archive.read(f"{root}/verify.ps1").decode()
    assert "& $VPy 'analysis.py' '$(touch pwned)' 'it''s' '‘‘x’’'" in ps1
    assert "Log '-- Запуск:" in ps1


def test_cli_builds_package(tmp_path: Path, capsys):
    output = tmp_path / "out.zip"
    assert main([str(EXAMPLES / "messy_lab_project"), "-o", str(output)]) == 0
    assert zipfile.is_zipfile(output)
    assert "[критично]" in capsys.readouterr().out
