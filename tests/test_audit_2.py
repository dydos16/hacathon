"""Регрессионные тесты по второму аудиту безопасности (коммит 0814113): F1–F5 из отчёта."""

import io
import pickle
import zipfile
from pathlib import Path

import pytest
import streamlit
from streamlit.testing.v1 import AppTest

from repropack import packer
from repropack.analysis import analyze
from repropack.intake import IntakeError, read_upload
from repropack.packer import PackOptions, build_zip
from repropack.secrets import file_text, find_secrets, is_secret_file, read_text, scan
APP = str(Path(__file__).parent.parent / "app.py")
MAIN = {"main.py": b"print(1)\n"}
PLANTED = "Zq7w" + "PlantedSecret42"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def upload(*files: tuple[str, bytes]) -> AppTest:
    app = AppTest.from_file(APP, default_timeout=60).run()
    app.file_uploader[0].set_value([(name, data, "application/octet-stream") for name, data in files]).run()
    return app


def packaged(files: dict[str, bytes]) -> zipfile.ZipFile:
    analysis = analyze(files)
    return zipfile.ZipFile(io.BytesIO(build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))))


def leaks(files: dict[str, bytes], needle: str) -> list[str]:
    archive = packaged(files)
    return [name for name in archive.namelist()
            if any(needle in archive.read(name).decode(e, "ignore") for e in ("utf-8", "utf-16-le", "utf-16-be"))]


# --- F1: байт NUL в начале текстового файла отключал поиск секретов ---

@pytest.mark.parametrize("name, data, needle", [
    ("cfg.py", b"\x00password = 'correct-horse-battery'\n", "correct-horse-battery"),
    ("data.csv", f"\x00id,key\n1,{AWS}\n".encode(), AWS),
    (".env.example", f"\x00\x00API_TOKEN={PLANTED}\n".encode(), PLANTED),
])
def test_nul_byte_does_not_turn_a_text_file_into_unscanned_binary(name, data, needle):
    assert leaks({**MAIN, name: data}, needle) == []


def test_utf16_without_bom_needs_many_zero_bytes():
    assert file_text("password: x\n".encode("utf-16-le"))[1] == "utf-16-le"
    assert file_text(b"\x00password = 'correct-horse-battery'\n", "cfg.py")[1] == "utf-8"  # один NUL — не UTF-16


def test_token_in_a_binary_file_stops_the_build_instead_of_leaking():
    blob = pickle.dumps({"aws": AWS, "weights": list(range(100))})
    analysis = analyze({**MAIN, "state.pkl": blob})
    [hit] = analysis.secrets
    assert hit.kind == "ключ AWS в двоичном файле" and hit.path == "state.pkl"
    assert any("не заменить" in i.detail for i in analysis.issues)
    with pytest.raises(ValueError, match="state.pkl"):
        build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))
    assert read_text(blob, "state.pkl") == "" and scan("weights.npy", b"\x93NUMPY\x01\x00" + bytes(1000)) == []


# --- F4: пропуски в поиске секретов ---

@pytest.mark.parametrize("name, line, needle", [
    ("cfg.py", 'password = "hunter2"', "hunter2"),
    ("cfg.py", f'DB_PASS = "{PLANTED}"', PLANTED),
    ("cfg.py", 'password = "correct horse battery"', "correct horse battery"),
    ("cfg.py", 'conn = "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=Zq7wAzure0123456789abcdefAB==;'
               'EndpointSuffix=core.windows.net"', "Zq7wAzure0123456789"),
    ("kube.yaml", "    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpaN3d", "LS0tLS1CRUdJTiBSU0Eg"),
    ("cfg.py", 'key = "SG.Zq7wPlantedSendGrid12.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"', "SG.Zq7w"),
    ("settings.ini", "[db]\npass = hunter22", "hunter22"),
], ids=["short-password", "db-pass", "password-with-spaces", "azure", "kubeconfig", "sendgrid", "ini-pass"])
def test_secrets_missed_by_the_first_audit_are_found_and_redacted(name, line, needle):
    assert find_secrets(name, line + "\n")
    assert leaks({**MAIN, name: (line + "\n").encode()}, needle) == []


@pytest.mark.parametrize("path", [".kube/config", "terraform.tfstate", "terraform.tfstate.backup", "credentials.yaml",
                                  "secrets.yaml", "prod.secrets", ".docker/config.json",
                                  "gcloud/application_default_credentials.json"])
def test_more_secret_files_are_excluded(path):
    assert is_secret_file(path)


def test_short_values_and_lookalike_names_in_scientific_code_are_not_secrets():
    """Порог для токенов и ключей прежний: в NLP-коде unk_token = "unknown" — не секрет; compass — не pass."""
    code = ('unk_token = "unknown"\nbos_token = "[BOS]"\ncompass = "north-east"\nbypass_token_check = True\n'
            'secrets.py\nconfig = load("config.yaml")\n')
    assert find_secrets("model.py", code) == []
    assert not is_secret_file("secrets.py") and not is_secret_file("config/config.json")


# --- F2: zip-бомба по коэффициенту сжатия ---

def test_archive_compressed_more_than_100_times_is_rejected():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("main.py", "print(1)\n")
        archive.writestr("data.csv", "0," * 15_000_000)  # 30 МБ нулей сжимаются в десятки КБ
    with pytest.raises(IntakeError, match="больше чем в 100 раз"):
        read_upload([("p.zip", buffer.getvalue())])


def test_package_is_built_once_per_upload_and_settings_not_on_every_rerun(monkeypatch):
    calls = []
    original = packer.build_zip
    monkeypatch.setattr(packer, "build_zip", lambda *args: calls.append(1) or original(*args))
    app = upload(("main.py", b"import numpy\n\nif __name__ == '__main__':\n    print(1)\n"))
    app.run()
    app.run()
    assert not app.exception and len(calls) == 1  # перерисовка без изменений — без новой сборки
    next(w for w in app.selectbox if w.label == "Python").set_value("3.12").run()
    assert len(calls) == 2  # изменили настройку — пакет собран заново


# --- F3: таблицы и список проблем не растут без предела ---

def test_huge_project_shows_bounded_tables_and_issue_lists():
    imports = "\n".join(f"import pkg_{i}" for i in range(320)).encode()
    app = upload(("main.py", imports + b"\nif __name__ == '__main__':\n    pass\n"))
    assert not app.exception
    assert len(app.dataframe[0].value) == 300  # таблица зависимостей
    captions = " ".join(c.value for c in app.caption)
    assert "ещё 20 попадут в requirements.txt без изменений" in captions and "первые 300 из 320" in captions
    assert any("… и ещё" in m.value for m in app.markdown)
    (_, options), (package, _) = app.session_state["build"]
    assert len(options.requirements) == 320 and package  # скрытые строки тоже ушли в requirements.txt


# --- F5: открыто по умолчанию ---

def test_environment_versions_need_a_local_server_or_explicit_permission(monkeypatch):
    original = streamlit.get_option
    monkeypatch.setattr(streamlit, "get_option",
                        lambda key: "0.0.0.0" if key == "server.address" else original(key))
    assert not AppTest.from_file(APP, default_timeout=30).run().checkbox  # сервер открыт в сеть — галочки нет
    monkeypatch.setenv("REPRO_LOCAL", "1")
    assert AppTest.from_file(APP, default_timeout=30).run().checkbox  # владелец разрешил явно


# --- Новый код verify-скриптов (поиск нужного Python, коммит 0b93a69) ---

@pytest.mark.parametrize("version", ["3.11; touch PWN", "$(id).1", "3.11'; calc; '", "3.11\n", "３.１１",
                                     "3." + "9" * 5000])
def test_python_version_cannot_inject_into_the_interpreter_search(version):
    """Версия попадает в «for version in …» verify.sh и в @('…') verify.ps1: только цифры и точка, короткая."""
    with pytest.raises(ValueError, match="Некорректная версия Python"):
        packer.render_package(analyze(MAIN), PackOptions("p", "main.py", version, ()))


def test_interpreter_search_lists_only_plain_versions():
    generated = packer.render_package(analyze(MAIN), PackOptions("p", "main.py", "3.12", ()))
    assert "  for version in 3.12 3.13 3.14; do" in generated["verify.sh"]
    assert "@('3.12', '3.13', '3.14')" in generated["verify.ps1"]
