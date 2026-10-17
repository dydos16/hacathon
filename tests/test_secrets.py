import codecs
import dataclasses
import io
import json
import os
from array import array
import time
import tracemalloc
import zipfile

import pytest

from repropack import packer
from repropack.analysis import analyze
from repropack.packer import ENV_TEMPLATE_HEADER, PackOptions, Requirement, build_zip, env_templates
from repropack.secrets import env_names, file_text, find_secrets, read_text, redact, redact_bytes

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
    (f'bot = Bot("123456789:{"AAHdemo" * 5}")', "AAHdemo" * 5, "Telegram"),
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
        if any(PLANTED in data.decode(encoding, "ignore") for encoding in ("utf-8", "utf-16-le", "utf-16-be")):
            found.append(name.split("/", 1)[1])
    return found


def notebook(source: str, output: str = "") -> bytes:
    outputs = [{"output_type": "stream", "name": "stdout", "text": [output]}] if output else []
    return json.dumps({"cells": [{"cell_type": "code", "source": [source], "outputs": outputs}],
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
    find_secrets(".env", text), redact(text, plain=True), env_names(".env", text)
    # Локально — доли секунды, на CI под измерением покрытия — пара секунд; квадратичный перебор — минуты
    assert time.perf_counter() - start < 10


# --- Находки повторного аудита: текст по содержимому, присваивания без кавычек, BOM, вымарывание всех файлов ---
MAIN = {"main.py": b"print(1)\n"}
ANTHROPIC_KEY = "sk-ant-api03-" + "Demo0" * 6


@pytest.mark.parametrize("name", ["data.csv", "run.ps1", "run.bat", "run.cmd", "train.log", "gui.pyw", "main.py.bak",
                                  "nginx.conf.j2", "my.cnf"])
def test_text_files_are_scanned_whatever_their_extension(name):
    """Текст узнаётся по содержимому, а не по расширению: ключ в .csv, .ps1, .log или копии .bak не уходит в пакет."""
    assert leaks({**MAIN, name: f'api_key = "{PLANTED}"\n'.encode()}) == []


@pytest.mark.parametrize("name", ["weights.npy", "blob"])
def test_binary_file_is_skipped_without_decoding_it_in_full(name):
    """Двоичный файл (NUL в первых 8 КБ) не декодируется целиком: 50 МБ случайных байт не съедают сотни МБ памяти."""
    data = b"\x93NUMPY\x01\x00" + os.urandom(50 * 2**20)
    tracemalloc.start()
    try:
        analysis = analyze({**MAIN, name: data})
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 10 * 2**20 and analysis.secrets == ()
    assert redact_bytes(name, data) is data


def test_binary_that_looks_like_utf16_is_not_text():
    """Нули через байт бывают и в двоичных данных (int16): управляющие символы в «тексте» выдают их."""
    assert read_text(array("h", [1, 2, 3] * 1000).tobytes()) == ""


def test_text_with_nul_after_the_first_8_kb_is_still_text():
    """Решение «текст или нет» — по первым 8 КБ: NUL дальше не делает лог двоичным."""
    text = f"{'x' * 9000}\napi_key = '{PLANTED}'\n\x00\n"
    assert leaks({**MAIN, "train.log": text.encode()}) == []


@pytest.mark.parametrize("name, data", [
    ("notes.txt", f"API_KEY={PLANTED}\n".encode()),
    ("notes.md", f"password: {PLANTED}\n".encode()),
    ("run.sh", f"export DB_PASSWORD={PLANTED}\n".encode()),
    ("docker-compose.yml", f"services:\n  db:\n    environment:\n      - DB_PASSWORD={PLANTED}\n".encode()),
    ("Dockerfile", f"FROM python:3.11\nENV DB_PASSWORD={PLANTED}\nARG API_TOKEN={PLANTED}\n".encode()),
    ("run.ps1", f'$env:DB_PASSWORD = "{PLANTED}"\n'.encode()),
    ("run.bat", f'set API_KEY={PLANTED}\r\nset "DB_PASSWORD={PLANTED}"\r\n'.encode()),
    ("exp.ipynb", notebook("print(f'token={token}')", f"token={PLANTED}\n")),
], ids=["txt", "md", "sh", "compose", "dockerfile", "powershell", "bat", "notebook-output"])
def test_unquoted_assignments_are_found_in_every_text_file(name, data):
    """«API_KEY=…» без кавычек ищется в любом тексте: заметки, скрипты оболочки, compose, Dockerfile, вывод ячеек."""
    assert leaks({**MAIN, name: data}) == []


@pytest.mark.parametrize("text", ["{not json", '{"cells": [{"outputs": [1]}]}', "[" * 100_000],
                         ids=["broken", "odd-output", "deep"])
def test_broken_notebook_is_scanned_as_plain_text(text):
    """Битый или странный JSON ноутбука не роняет анализ: ключ в нём находится обычными шаблонами."""
    assert find_secrets("exp.ipynb", text) == []
    assert find_secrets("exp.ipynb", f'{text}\nAPI_KEY = "{ANTHROPIC_KEY}"')


def test_notebook_value_that_cannot_be_replaced_stops_the_build():
    """Вывод записан с иным экранированием (\\/): заменить значение нельзя — пакет не собирается, а не утекает."""
    raw = notebook("print(token)", f"token=abc/{PLANTED}\n").replace(b"abc/", b"abc\\/")
    assert find_secrets("exp.ipynb", raw.decode())
    with pytest.raises(ValueError, match="не удалось заменить"):
        build_zip(analyze({**MAIN, "exp.ipynb": raw}), PackOptions("p", "main.py", "3.11", ()))


def test_unquoted_values_in_code_and_prose_are_not_secrets():
    """В коде секрет — только литерал в кавычках: `password = get_password()` — не секрет; описание параметра — тоже."""
    code = "password = get_password()\ntoken = tokenizer(text)\napi_key = load_api_key_from_vault\n"
    assert find_secrets("main.py", code) == [] and find_secrets("exp.ipynb", notebook(code).decode()) == []
    prose = ("token: Authentication token for the API\nmax_tokens: 512\nAPI_KEY=your-api-key-here\n"
             "password: ********\nTOKEN_URL=https://example.org/oauth\n")
    assert find_secrets("README.md", prose) == [] and redact_bytes("README.md", prose.encode()) == prose.encode()


@pytest.mark.parametrize("name, text", [
    ("fs.pyx", "access_key = frombytes(opts.GetAccessKey())\nself.key_access_token = key_access_token\n"),
    ("task_group.h", "StopToken = StopToken::Unstoppable());\n"),
    ("README.md", "```python\npassword = get_password()\n```\n"),
    ("index.html.j2", "mapboxApiKey: '{{mapbox_key}}',\napi_key = \"${API_KEY}\"\n"),
    ("server.py", 'url = str(self.replace(password="********"))\nAPI_KEY = "your-api-key-here"\n'),
], ids=["cython", "cpp", "markdown-code", "template", "masked"])
def test_code_in_any_language_and_placeholders_are_not_secrets(name, text):
    """Cython и C++ — тоже код; вызов функции, {{шаблон}}, ${VAR}, ******** и your-… — не значения секретов."""
    assert find_secrets(name, text) == []


@pytest.mark.parametrize("data, cleaned", [
    (codecs.BOM_UTF8 + f"password: {PLANTED}\n".encode(), codecs.BOM_UTF8 + b"password: <REDACTED>\n"),
    (f"password: {PLANTED}\n".encode("utf-16-le"), "password: <REDACTED>\n".encode("utf-16-le")),
    (f"password: {PLANTED}\n".encode("utf-16-be"), "password: <REDACTED>\n".encode("utf-16-be")),
], ids=["utf8-bom", "utf16le-no-bom", "utf16be-no-bom"])
def test_bom_or_missing_utf16_bom_does_not_hide_a_secret(data, cleaned):
    """BOM перед первой строкой и UTF-16 без BOM не прячут секрет; вымаранный файл остаётся в своей кодировке."""
    assert leaks({**MAIN, "config.yaml": data}) == []
    assert redact_bytes("config.yaml", data) == cleaned


@pytest.mark.parametrize("source", [
    f'password = "<REDACTED>"; DB_PASSWORD = "{PLANTED}"\n',
    f'KEYS = {{"a": "sk-ant-api03-{PLANTED}aaaa", "b": "sk-ant-api03-{PLANTED}bbbb"}}\n',
    f'KEY = "sk-ant-api03-" "{PLANTED}EXAMPLEEXAMPLE"\n',
    f'KEY = ("sk-ant-api03-{PLANTED}"\n       "EXAMPLEEXAMPLE{PLANTED}")\n',
], ids=["after-redacted", "two-keys", "split-literal", "split-across-lines"])
def test_every_secret_on_a_line_and_split_keys_are_redacted(source):
    """Все совпадения в строке, ключ из соседних литералов и строка с уже вымаранным значением — всё вымарывается."""
    assert leaks({"main.py": source.encode()}) == []
    assert find_secrets("main.py", source)


def test_split_key_is_replaced_by_one_valid_literal():
    """Ключ из нескольких литералов заменяется целиком: остаётся один литерал, код по-прежнему разбирается."""
    assert redact(f'KEY = ("{ANTHROPIC_KEY[:13]}"\n       "{ANTHROPIC_KEY[13:]}")\n') == 'KEY = ("<REDACTED>")\n'
    harmless = 'NAME = ("hf_" "hub")\n'  # склейка не похожа на токен — не трогаем
    assert redact(harmless) == harmless and find_secrets("main.py", harmless) == []


def test_every_text_file_is_redacted_even_if_analysis_missed_it():
    """Вымарывается каждый текстовый файл пакета, а не только те, где анализ нашёл секрет."""
    analysis = dataclasses.replace(analyze({"main.py": f'API_KEY = "{ANTHROPIC_KEY}"\n'.encode()}), secrets=())
    archive = zipfile.ZipFile(io.BytesIO(build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))))
    assert ANTHROPIC_KEY.encode() not in archive.read("p-repro/project/main.py")


def test_safety_check_covers_every_text_file(monkeypatch):
    """Проверка после вымарывания идёт по каждому текстовому файлу: пропуск анализа не открывает дорогу секрету."""
    monkeypatch.setattr(packer, "redact_bytes", lambda path, data: data)
    analysis = dataclasses.replace(analyze({"main.py": f'API_KEY = "{ANTHROPIC_KEY}"\n'.encode()}), secrets=())
    with pytest.raises(ValueError, match="не удалось заменить"):
        build_zip(analysis, PackOptions("p", "main.py", "3.11", ()))


@pytest.mark.parametrize("token, kind", [
    ("pypi-AgEIcHlwaS5vcmc" + "Q0RFTU8" * 10, "PyPI"),
    ("github_pat_11" + "DEMO0" * 4 + "_" + "Demo" * 15, "GitHub"),
    ("ASIA" + "DEMO" * 4, "AWS"),
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBGDemo" + PLANTED + "\n=Demo\n-----END PGP PRIVATE KEY BLOCK-----",
     "приватный ключ"),
], ids=["pypi", "github-fine-grained", "aws-temporary", "pgp"])
def test_more_token_formats_are_found_and_redacted(token, kind):
    """Токены PyPI, fine-grained GitHub, временные ключи AWS (ASIA…) и закрытые ключи PGP — тоже секреты."""
    [hit] = find_secrets("notes.txt", f"{token}\n")
    assert kind in hit.kind
    cleaned = redact(f"{token}\n")
    assert token.split("\n")[0] not in cleaned and PLANTED not in cleaned


def test_env_template_lists_only_real_names_even_with_multiline_values_and_utf16():
    """Многострочное значение в кавычках не даёт ложных имён в .env.example, а .env в UTF-16 читается как текст."""
    text = ('CERT="-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU=\nQUJD=\n-----END CERTIFICATE-----"\n'
            "JSON='{\nNOT_A_NAME=2\n}'\nESCAPED=\"a\\\"\nFAKE=1\"\nOTHER=1\n")
    assert env_names(".env", text) == ["CERT", "JSON", "ESCAPED", "OTHER"]
    analysis = analyze({**MAIN, ".env": "API_KEY=abc\nDB_URL=x\n".encode("utf-16")})
    assert env_templates(analysis) == {".env.example": ENV_TEMPLATE_HEADER + "API_KEY=\nDB_URL=\n"}
    assert any("API_KEY, DB_URL" in issue.detail for issue in analysis.issues)


@pytest.mark.parametrize("files, run_args, requirements", [
    ({}, f"--key {ANTHROPIC_KEY}", ()),
    ({f"keys/{ANTHROPIC_KEY}.txt": b"x = 1\n"}, "", ()),
    ({}, "", (Requirement("numpy", comment=f"ключ {ANTHROPIC_KEY}"),)),
], ids=["run-args", "file-name", "requirement-comment"])
def test_package_with_a_key_in_generated_files_or_names_is_refused(files, run_args, requirements):
    """Ключ в аргументах запуска, имени файла или таблице зависимостей — пакет не собирается, ключ не в сообщении."""
    analysis = analyze({**MAIN, **files})
    with pytest.raises(ValueError, match="секрет") as error:
        build_zip(analysis, PackOptions("p", "main.py", "3.11", requirements, run_args))
    assert ANTHROPIC_KEY not in str(error.value)


def test_large_text_data_file_is_scanned_quickly():
    """Каждый текстовый файл теперь сканируется трижды (анализ, вымарывание, проверка): CSV на 16 МБ — за секунды."""
    rows = "".join(f"{i},2024-01-01T12:00:00,{i * 0.37:.6f},class_{i % 7},sample note {i}\n" for i in range(330_000))
    files = {**MAIN, "data.csv": f"id,time,value,label,comment\n{rows}".encode()}
    started = time.perf_counter()
    build_zip(analyze(files), PackOptions("p", "main.py", "3.11", ()))
    # Было ~9 с: шаблоны начинались с \b или (?i), и re пробовал совпадение в каждой позиции
    assert time.perf_counter() - started < 5
