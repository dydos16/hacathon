"""Эвристический поиск секретов: подсказка, а не полный аудит. Значения никогда не показываются целиком."""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

SECRET_FILE_NAMES = {".env", ".netrc", ".pgpass", "id_rsa", "id_ed25519", "credentials.json",
                     "client_secret.json", "secrets.toml", ".pypirc"}
SECRET_FILE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore"}
# .env.example и подобные — шаблоны переменных для коллег: файл остаётся в пакете, но сканируется
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
TEXT_SUFFIXES = {".py", ".ipynb", ".txt", ".cfg", ".ini", ".toml", ".yml", ".yaml", ".json", ".md", ".sh",
                 ".env", ".conf", ".properties", ".xml", ".r", ".sql", ".js", ""}
PATTERNS = [
    ("приватный ключ", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("ключ AWS", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("токен GitHub", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})\b")),
    ("ключ OpenAI/Anthropic", re.compile(r"\b(sk-(?:ant-)?[A-Za-z0-9_-]{20,})\b")),
    ("токен Slack", re.compile(r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b")),
    ("токен Telegram-бота", re.compile(r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b")),
    ("ключ Google API", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})(?![\w-])")),
    ("токен Hugging Face", re.compile(r"\b(hf_[A-Za-z0-9]{30,})\b")),
    ("ключ Stripe", re.compile(r"\b([rs]k_live_[0-9A-Za-z]{20,})\b")),
    ("токен JWT", re.compile(r"\b(eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,})")),
    # scheme://user:пароль@host; подстановки ({password}, ${PW}, %(pw)s) и примеры из документации
    # (user:password@, xxx:xxx@) — не секрет
    ("пароль в адресе подключения", re.compile(
        r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"\[]*:(?!(?i:x+|\*+|pass|passwd|password|pwd|secret)@)"
        r"([^\s:/@'\"{}$<>%]+)@")),
    # Имя переменной должно заканчиваться ключевым словом: API_KEY, db_password — да, tokenizer, max_tokens — нет
    ("пароль/токен в коде", re.compile(
        r"""(?i)\b\w*?(?:api_?key|secret(?:_?key)?|token|passw(?:or)?d|pwd)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']""")),
]
MASK_REVEAL_FROM = 20
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)


@dataclass(frozen=True)
class SecretHit:
    path: str
    line: int
    kind: str
    masked: str


def is_secret_file(path: str) -> bool:
    name = PurePosixPath(path).name
    if name.startswith(".env.") and name.endswith(ENV_TEMPLATE_SUFFIXES):
        return False
    return (name in SECRET_FILE_NAMES or name.startswith(".env.")
            or PurePosixPath(name).suffix.lower() in SECRET_FILE_SUFFIXES)


def _is_text(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.startswith(".env") or PurePosixPath(name).suffix.lower() in TEXT_SUFFIXES


def _mask(value: str) -> str:
    """Начало и конец — только у длинных значений: у короткого пароля 6 символов — это почти весь пароль."""
    return f"{value[:4]}…{value[-2:]}" if len(value) >= MASK_REVEAL_FROM else "…"


def _redact_match(match: re.Match) -> str:
    """Заменяет только само значение (группу), а не все его вхождения: в «password = 'password'» имя остаётся."""
    group = match.lastindex or 0
    start, end = match.start(group) - match.start(), match.end(group) - match.start()
    return f"{match.group(0)[:start]}<REDACTED>{match.group(0)[end:]}"


def find_secrets(path: str, text: str) -> list[SecretHit]:
    if not _is_text(path):
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
        text = pattern.sub(_redact_match, text)
    return text


def redact_bytes(data: bytes) -> bytes:
    """redact() для файла целиком без смены кодировки.

    Файл не в UTF-8 (например, cp1251) читается как latin-1: эта кодировка переводит байты в символы
    один к одному, поэтому всё, кроме вымаранных значений, остаётся побайтно прежним.
    """
    try:
        return redact(data.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError:
        return redact(data.decode("latin-1")).encode("latin-1")
