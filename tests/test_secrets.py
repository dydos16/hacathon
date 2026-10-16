import io
import json
import time
import zipfile

import pytest

from repropack.analysis import analyze
from repropack.packer import PackOptions, build_zip
from repropack.secrets import env_names, file_text, find_secrets, redact, redact_bytes

# Поддельные значения нужного формата: собраны из частей, чтобы сканеры секретов не принимали тест за утечку
GOOGLE_KEY = "AIza" + "Sy" + "D3m0" * 8 + "x"
HF_TOKEN = "hf_" + "DemoToken" * 4
STRIPE_KEY = "sk_live_" + "4eC39Hq" * 4
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJkZW1vIn0" + ".c2lnbmF0dXJlZGVtbw"


@pytest.mark.parametrize("line, secret, kind", [
    (f'genai.configure(api_key="{GOOGLE_KEY}")', GOOGLE_KEY, "Google"),
    (f'login("{HF_TOKEN}")', HF_TOKEN, "Hugging Face"),
    (f'stripe.api_key = "{STRIPE_KEY}"', STRIPE_KEY, "Stripe"),
    (f'headers = {{"Authorization": "Bearer {JWT}"}}', JWT, "JWT"),
    ('engine = create_engine("postgresql://lab:s3cr3t-Pa55@db.lab.local:5432/exp")', "s3cr3t-Pa55", "адрес"),
    ('r = redis.from_url("redis://:hunter2hunter2@cache:6379/0")', "hunter2hunter2", "адрес"),
])
def test_cloud_tokens_and_passwords_in_urls_are_found_and_redacted(line, secret, kind):
    [hit] = find_secrets("a.py", line)
    assert kind in hit.kind and secret not in hit.masked
    assert secret not in redact(line) and "<REDACTED>" in redact(line)


def test_typical_scientific_code_is_not_flagged():
    text = "\n".join([
        'path = hf_hub_download(repo_id="bert-base-uncased", filename="config.json")',
        'hf_token_env = "HF_TOKEN"',
        'url = "https://example.org/data/measurements.csv"',
        'db = "postgresql://lab@localhost/experiments"',
        'dsn = f"postgresql://{user}:{password}@{host}/db"',
        'proxy = "http://proxy.lab.local:3128/path@v2"',
        'repo = "git+ssh://git@github.com/lab/tools.git"',
        'key_column = "AIzawa_station_id"',
        'example = "xxx+xxx://xxx:xxx@xxx:xxx/xxx"',
        '"""Прокси в виде scheme://[user:passwd@]proxy.server:port или postgresql://user:password@host"""',
    ])
    assert find_secrets("a.py", text) == []
    assert redact(text) == text


def test_redaction_never_touches_the_variable_name():
    assert redact('password = "password"\n') == 'password = "<REDACTED>"\n'
    assert redact("db_password = 'password1'\n") == "db_password = '<REDACTED>'\n"


def test_short_secret_is_not_shown_even_partially():
    [hit] = find_secrets("a.py", 'pwd = "abcdefghij"\n')
    assert "abc" not in hit.masked and "ij" not in hit.masked


# --- Находки аудита безопасности: каждая из этих загрузок раньше уходила в пакет с открытым значением ---
PLANTED = "Zq7w" + "PlantedSecret42"


def leaks(files: dict[str, bytes]) -> list[str]:
    """Пути внутри собранного пакета, где осталось открытое значение PLANTED."""
    analysis = analyze(files)
    package = zipfile.ZipFile(io.BytesIO(build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))))
    found = []
    for name in package.namelist():
        data = package.read(name)
        if any(PLANTED in data.decode(encoding, "ignore") for encoding in ("utf-8", "utf-16")):
            found.append(name.split("/", 1)[1])
    return found


def notebook(source: str) -> bytes:
    return json.dumps({"cells": [{"cell_type": "code", "source": [source], "outputs": []}],
                       "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1).encode()


@pytest.mark.parametrize("extra", [
    {"exp.ipynb": notebook(f'API_KEY = "{PLANTED}"\n')},                     # кавычки в JSON — \"…\"
    {"config.yaml": f"db_password: {PLANTED}\n".encode()},                   # без кавычек
    {"settings.ini": f"[db]\npassword = {PLANTED}\n".encode()},
    {".env.example": f"API_TOKEN={PLANTED}\n".encode()},                    # «шаблон» с настоящим значением
    {"prod.env": f"DB_PASSWORD={PLANTED}\n".encode()},
    {".ENV": f"DB_PASSWORD={PLANTED}\n".encode()},
    {".envrc": f"export API_TOKEN={PLANTED}\n".encode()},
    {".aws/credentials": f"[default]\naws_secret_access_key = {PLANTED}\n".encode()},
    {".npmrc": f"//registry.npmjs.org/:_authToken={PLANTED}\n".encode()},
    {"requirements.txt": f"--extra-index-url https://user:{PLANTED}@pypi.example/simple\n".encode("utf-16")},
    {"requirements.txt": f"--index-url https://{PLANTED}@pypi.example/simple\nnumpy\n".encode()},
    {"config.json": json.dumps({"api_key": PLANTED}).encode("utf-16")},
    {"main.py": f'exec(fetch("https://user:{PLANTED}@host.example/x"))\n'.encode()},  # деталь проблемы в REPORT
], ids=["ipynb", "yaml", "ini", "env-example", "prod.env", "ENV", "envrc", "aws", "npmrc", "utf16-req",
        "index-token", "utf16-json", "exec-detail"])
def test_planted_secret_never_reaches_the_package(extra):
    assert leaks({"main.py": b"print(1)\n", **extra}) == []


def test_utf16_file_is_redacted_in_its_own_encoding():
    original = f"--extra-index-url https://user:{PLANTED}@pypi.example/simple\n".encode("utf-16")
    redacted = redact_bytes("requirements.txt", original)
    # для адреса индекса прячется вся пара «логин:токен» — у частных индексов логин тоже бывает токеном
    assert redacted.decode("utf-16") == "--extra-index-url https://<REDACTED>@pypi.example/simple\n"


def test_cp1251_secret_after_cyrillic_word_is_redacted_where_it_is_found():
    token = "ghp_" + "A1b2C3d4" * 5
    original = f"x = 1  # токен{token}\n".encode("cp1251")
    [hit] = find_secrets("main.py", file_text(original)[0])
    assert "GitHub" in hit.kind and token.encode() not in redact_bytes("main.py", original)


def test_config_placeholders_and_redacted_values_are_not_secrets():
    text = "password = ${DB_PASSWORD}\ntoken: <your-token>\napi_key = %(key)s\nmax_tokens: 512\nsecret = <REDACTED>\n"
    assert find_secrets("settings.ini", text) == []


@pytest.mark.parametrize("text", ["a." * 200_000, "eyJ-" * 100_000, "\n" * 200_000, "a" * 200_000,
                                  "password" * 50_000], ids=["dots", "jwt", "newlines", "word", "keyword"])
def test_secret_patterns_are_linear_on_adversarial_input(text):
    start = time.perf_counter()
    find_secrets(".env", text), redact(text, config=True), env_names(".env", text)
    # Локально — доли секунды, на CI под измерением покрытия — пара секунд; квадратичный перебор — минуты
    assert time.perf_counter() - start < 10
