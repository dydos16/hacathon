import io
import unicodedata
import zipfile
from pathlib import Path

import pytest

from repropack import intake
from repropack.intake import IntakeError, read_directory, read_upload
from repropack.secrets import find_secrets, is_secret_file, redact, redact_bytes

FAKE_KEY = "sk-DEMO0000000000000000000000000000fake"


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def patch_headers(archive: bytes, local: int, central: int, value: bytes) -> bytes:
    """Записывает value по смещению в локальном заголовке и в записи центрального каталога."""
    data = bytearray(archive)
    start = data.find(b"PK\x01\x02")
    data[local:local + len(value)] = value
    data[start + central:start + central + len(value)] = value
    return bytes(data)


PLAIN = make_zip({"main.py": b"print(1)"})
DATA_OFFSET = 30 + len("main.py")  # данные идут сразу за локальным заголовком и именем файла


def test_zip_common_root_is_stripped_and_junk_skipped():
    data = make_zip({"proj/main.py": b"print(1)", "proj/__pycache__/main.pyc": b"x",
                     "proj/.venv/lib/x.py": b"", "proj/.DS_Store": b""})
    assert read_upload([("proj.zip", data)]) == {"main.py": b"print(1)"}


def test_zip_without_common_root_keeps_paths():
    files = read_upload([("p.zip", make_zip({"main.py": b"", "lib/util.py": b""}))])
    assert set(files) == {"main.py", "lib/util.py"}


@pytest.mark.parametrize("bad", ["../evil.py", "/etc/passwd.py", "C:/evil.py", "a/../../evil.py"])
def test_zip_slip_paths_are_rejected(bad):
    with pytest.raises(IntakeError):
        read_upload([("p.zip", make_zip({bad: b"", "main.py": b""}))])


def test_control_characters_in_file_names_are_rejected():
    with pytest.raises(IntakeError, match="символ"):
        read_upload([("p.zip", make_zip({"a\nb.py": b"x = 1"}))])


def test_zip_bomb_limit(monkeypatch):
    monkeypatch.setattr(intake, "MAX_UNPACKED_BYTES", 10)
    with pytest.raises(IntakeError, match="zip-бомба"):
        read_upload([("p.zip", make_zip({"main.py": b"x" * 100}))])


@pytest.mark.parametrize("limit, value", [("MAX_ARCHIVE_BYTES", 10), ("MAX_FILES", 1)])
def test_archive_size_and_file_count_limits(monkeypatch, limit, value):
    monkeypatch.setattr(intake, limit, value)
    with pytest.raises(IntakeError):
        read_upload([("p.zip", make_zip({"main.py": b"x = 1", "b.py": b""}))])


@pytest.mark.parametrize("archive, message", [
    (patch_headers(PLAIN, 6, 8, b"\x01\x00"), "паролем"),        # флаг шифрования
    (patch_headers(PLAIN, 8, 10, b"\x63\x00"), "распаковать"),   # метод сжатия 99 (AES) не поддерживается
    (PLAIN[:DATA_OFFSET] + b"X" + PLAIN[DATA_OFFSET + 1:], "распаковать"),  # данные не сходятся с CRC
])
def test_protected_or_damaged_archives_are_rejected_not_crashing(archive, message):
    with pytest.raises(IntakeError, match=message):
        read_upload([("p.zip", archive)])


def test_rejects_upload_without_python_and_broken_zip():
    with pytest.raises(IntakeError):
        read_upload([("data.csv", b"a,b")])
    with pytest.raises(IntakeError, match="ZIP"):
        read_upload([("p.zip", b"not a zip")])


def test_plain_files_are_put_in_root_and_junk_skipped():
    files = read_upload([("main.py", b"import x"), ("data.csv", b"1"), (".DS_Store", b"")])
    assert set(files) == {"main.py", "data.csv"}


def test_directory_skips_junk_and_enforces_limits(tmp_path: Path, monkeypatch):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("x = 1")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "util.py").write_text("y = 2")
    (tmp_path / "main.py").write_text("print(1)")
    assert read_directory(tmp_path) == {"main.py": b"print(1)", "src/util.py": b"y = 2"}
    monkeypatch.setattr(intake, "MAX_FILES", 1)
    with pytest.raises(IntakeError, match="слишком большая"):
        read_directory(tmp_path)


def test_zip_names_from_windows_and_macos_keep_cyrillic():
    """Проводник Windows пишет кириллицу в cp866 без флага UTF-8, часть архиваторов — UTF-8 без флага,
    а macOS раскладывает «й»/«ё» на букву и диакритику (NFD)."""
    cp866, utf8 = "данные.csv".encode("cp866"), "опыт.xlsx".encode()
    archive = make_zip({"main.py": b"", "A" * len(cp866): b"1", "B" * len(utf8): b"2",
                        unicodedata.normalize("NFD", "серия_ё.csv"): b"3"})
    archive = archive.replace(b"A" * len(cp866), cp866).replace(b"B" * len(utf8), utf8)
    assert set(read_upload([("p.zip", archive)])) == {"main.py", "данные.csv", "опыт.xlsx", "серия_ё.csv"}


def test_junk_does_not_count_towards_archive_limits(monkeypatch):
    monkeypatch.setattr(intake, "MAX_FILES", 2)
    monkeypatch.setattr(intake, "MAX_UNPACKED_BYTES", 10)
    junk = {f".git/objects/{i}": b"x" * 100 for i in range(5)}
    assert read_upload([("p.zip", make_zip({"main.py": b"x = 1", "._main.py": b"\x00\x05\x16\x07", **junk}))]) \
        == {"main.py": b"x = 1"}


def test_same_path_uploaded_twice_with_different_content_is_rejected():
    assert read_upload([("main.py", b"x"), ("main.py", b"x")]) == {"main.py": b"x"}
    with pytest.raises(IntakeError, match="дважды"):
        read_upload([("p.zip", make_zip({"main.py": b"old"})), ("main.py", b"new")])


@pytest.mark.parametrize("limit, value", [("MAX_FILES", 2), ("MAX_UNPACKED_BYTES", 10)])
def test_limits_apply_to_all_uploads_together(monkeypatch, limit, value):
    monkeypatch.setattr(intake, limit, value)
    with pytest.raises(IntakeError, match="Загрузка слишком большая"):
        read_upload([("a.py", b"x = 1"), ("p.zip", make_zip({"b.py": b"y = 2"})), ("c.py", b"z = 3")])


def test_secrets_are_found_masked_and_redacted():
    text = f'API_KEY = "{FAKE_KEY}"\npassword = "hunter2hunter2"\nx = 1\n'
    hits = find_secrets("a.py", text)
    assert [h.line for h in hits] == [1, 2]
    assert all("0000000000" not in h.masked for h in hits)
    cleaned = redact(text)
    assert "sk-DEMO" not in cleaned and "hunter2" not in cleaned and "x = 1" in cleaned


def test_ordinary_names_containing_token_are_not_secrets():
    text = 'tokenizer = "bert-base-uncased"\nmax_tokens = "100000000"\nTOKEN_URL = "https://example.org/x"\n'
    assert find_secrets("a.py", text) == []
    assert redact(text) == text


def test_private_key_body_is_redacted_entirely():
    text = "KEY = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0demo\n-----END RSA PRIVATE KEY-----'''\n"
    assert find_secrets("a.py", text)[0].kind == "приватный ключ"
    assert "MIIEpAIBAAKCAQEA0demo" not in redact(text)


def test_secret_files_are_recognized():
    assert is_secret_file(".env") and is_secret_file("keys/server.pem") and is_secret_file(".env.local")
    assert not is_secret_file("env.py")


def test_env_templates_are_kept_but_still_scanned():
    assert not is_secret_file(".env.example") and not is_secret_file("config/.env.sample")
    assert find_secrets(".env.example", f"OPENAI_API_KEY={FAKE_KEY}\n")


def test_config_files_are_scanned_regardless_of_suffix_case():
    assert find_secrets("settings.CFG", 'password = "hunter2hunter2"\n')
    assert find_secrets("app.conf", 'db_password = "hunter2hunter2"\n')
    assert find_secrets("photo.png", 'password = "hunter2hunter2"\n') == []


def test_redaction_keeps_the_original_file_encoding():
    original = f"# комментарий\nAPI_KEY = '{FAKE_KEY}'\n".encode("cp1251")
    assert redact_bytes(original) == original.replace(FAKE_KEY.encode(), b"<REDACTED>")
    assert redact_bytes(f"ключ = '{FAKE_KEY}'".encode()) == "ключ = '<REDACTED>'".encode()


def test_uploaded_folder_keeps_subfolders_and_leaves_inner_zip_alone():
    files = read_upload([("lab/main.py", b"x"), ("lab/helpers/util.py", b"y"), ("lab/data.zip", b"z"),
                         ("lab/.git/HEAD", b"h")], keep_paths=True)
    assert files == {"main.py": b"x", "helpers/util.py": b"y", "data.zip": b"z"}


def test_uploaded_folder_still_rejects_paths_outside_it():
    with pytest.raises(IntakeError, match="Небезопасный путь"):
        read_upload([("lab/main.py", b""), ("lab/../../etc/evil.py", b"")], keep_paths=True)
