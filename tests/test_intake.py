import io
import zipfile

import pytest

from repropack import intake
from repropack.intake import IntakeError, read_upload
from repropack.secrets import find_secrets, is_secret_file, redact


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_zip_common_root_is_stripped_and_junk_skipped():
    data = make_zip({"proj/main.py": b"print(1)", "proj/__pycache__/main.pyc": b"x",
                     "proj/.venv/lib/x.py": b"", "proj/.DS_Store": b""})
    assert read_upload([("proj.zip", data)]) == {"main.py": b"print(1)"}


@pytest.mark.parametrize("bad", ["../evil.py", "/etc/passwd.py", "C:/evil.py", "a/../../evil.py"])
def test_zip_slip_paths_are_rejected(bad):
    with pytest.raises(IntakeError):
        read_upload([("p.zip", make_zip({bad: b"", "main.py": b""}))])


def test_zip_bomb_limit(monkeypatch):
    monkeypatch.setattr(intake, "MAX_UNPACKED_BYTES", 10)
    with pytest.raises(IntakeError, match="zip-бомба"):
        read_upload([("p.zip", make_zip({"main.py": b"x" * 100}))])


def test_rejects_upload_without_python_and_broken_zip():
    with pytest.raises(IntakeError):
        read_upload([("data.csv", b"a,b")])
    with pytest.raises(IntakeError, match="ZIP"):
        read_upload([("p.zip", b"not a zip")])


def test_plain_files_are_put_in_root():
    files = read_upload([("main.py", b"import x"), ("data.csv", b"1")])
    assert set(files) == {"main.py", "data.csv"}


def test_secrets_are_found_masked_and_redacted():
    text = 'API_KEY = "sk-DEMO0000000000000000000000000000fake"\npassword = "hunter2hunter2"\nx = 1\n'
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
