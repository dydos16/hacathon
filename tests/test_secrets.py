import pytest

from repropack.secrets import find_secrets, redact

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
