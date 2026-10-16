"""Эвристический поиск секретов: подсказка, а не полный аудит. Значения никогда не показываются целиком."""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

SECRET_FILE_NAMES = {".env", ".envrc", ".netrc", ".pgpass", "id_rsa", "id_ed25519", "credentials.json",
                     "client_secret.json", "secrets.toml", ".pypirc"}
SECRET_FILE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore"}
TEXT_SUFFIXES = {".py", ".ipynb", ".txt", ".cfg", ".ini", ".toml", ".yml", ".yaml", ".json",
                 ".md", ".sh", ".env", ""}
PATTERNS = [
    ("приватный ключ", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("ключ AWS", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("токен GitHub", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})\b")),
    ("ключ OpenAI/Anthropic", re.compile(r"\b(sk-(?:ant-)?[A-Za-z0-9_-]{20,})\b")),
    ("токен Slack", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b")),
    ("токен Telegram-бота", re.compile(r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b")),
    # Имя переменной должно заканчиваться ключевым словом: API_KEY, db_password — да, tokenizer, max_tokens — нет
    ("пароль/токен в коде", re.compile(
        r"""(?i)\b\w*?(?:api_?key|secret(?:_?key)?|token|passw(?:or)?d|pwd)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']""")),
]
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*?(?=\n\s*\n|\Z))",
    re.S,
)


@dataclass(frozen=True)
class SecretHit:
    path: str
    line: int
    kind: str
    masked: str


def is_secret_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return (name in SECRET_FILE_NAMES or name.startswith(".env.")
            or PurePosixPath(path).suffix in SECRET_FILE_SUFFIXES)


def _mask(value: str) -> str:
    return f"{value[:4]}…{value[-2:]}" if len(value) > 8 else "…"


def find_secrets(path: str, text: str) -> list[SecretHit]:
    if PurePosixPath(path).suffix not in TEXT_SUFFIXES:
        return []
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in PATTERNS:
            match = pattern.search(line)
            if match:
                hits.append(SecretHit(path, number, kind, _mask(match.group(match.lastindex or 0))))
                break
    return hits


def redact(text: str) -> str:
    """Заменяет найденные значения на <REDACTED>, остальной текст не трогает."""
    text = PRIVATE_KEY_BLOCK.sub("<REDACTED PRIVATE KEY>", text)
    for _, pattern in PATTERNS:
        text = pattern.sub(lambda m: m.group(0).replace(m.group(m.lastindex or 0), "<REDACTED>"), text)
    return text
