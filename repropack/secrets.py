"""Эвристический поиск секретов: подсказка, а не полный аудит. Значения никогда не показываются целиком."""

import codecs
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

# Имена сравниваются без учёта регистра: .ENV в Windows — тот же .env
SECRET_FILE_NAMES = {".env", ".envrc", ".netrc", ".pgpass", ".pypirc", ".npmrc", ".git-credentials", ".dockercfg",
                     "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", "credentials.json",
                     "client_secret.json", "service_account.json", "secrets.toml"}
SECRET_FILE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".p8", ".ppk", ".tfvars"}
# .env.example и подобные — шаблоны переменных для коллег: файл остаётся в пакете, но сканируется
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
TEXT_SUFFIXES = {".py", ".ipynb", ".txt", ".cfg", ".ini", ".toml", ".yml", ".yaml", ".json", ".md", ".sh",
                 ".env", ".conf", ".properties", ".xml", ".r", ".sql", ".js", ""}
# В конфигах значение пишут без кавычек (password = abc, token: abc) — там ищем и такие присваивания
CONFIG_SUFFIXES = {".cfg", ".ini", ".toml", ".yml", ".yaml", ".conf", ".properties", ".env", ""}
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
    # Начало токена — только после не-словесного символа: иначе на строке вида «eyJ-eyJ-…» перебор квадратичный
    ("токен JWT", re.compile(r"(?<![\w-])(eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,})")),
    # scheme://user:пароль@host; подстановки ({password}, ${PW}, %(pw)s) и примеры из документации
    # (user:password@, xxx:xxx@) — не секрет. Схема — с начала слова и не длиннее 30 символов (без ReDoS)
    ("пароль в адресе подключения", re.compile(
        r"(?<![\w+.-])[a-z][a-z0-9+.-]{0,30}://[^\s:/@'\"\[]*:(?!(?i:x+|\*+|pass|passwd|password|pwd|secret)@)"
        r"([^\s:/@'\"{}$<>%]+)@")),
    # pip: --index-url https://ТОКЕН@host — у частных индексов токен часто стоит вместо имени пользователя
    ("токен в адресе индекса пакетов", re.compile(
        r"(?i)(?:index-url|find-links)[ \t=]+[a-z][a-z0-9+.-]{0,30}://([^\s/@'\"]+)@")),
    # Имя переменной должно заканчиваться ключевым словом: API_KEY, db_password — да, tokenizer, max_tokens — нет.
    # Кавычка может быть экранирована (\"…\" внутри JSON ноутбука); длина имени ограничена — без ReDoS
    ("пароль/токен в коде", re.compile(
        r"(?i)\b\w{0,40}?(?:api_?key|access_?key|private_?key|secret(?:_?key)?|token|passw(?:or)?d|pwd)\b"
        r"""\\?["']?[ \t]*[:=][ \t]*\\?["']([^"'\s\\]{8,})\\?["']""")),
]
# То же присваивание без кавычек — только для конфигов (.env, .ini, .yaml…): «password = abc», «_authToken=abc»
CONFIG_ASSIGNMENT = re.compile(
    r"(?im)^[ \t]*(?:export[ \t]+)?[\w./:@-]{0,80}?(?:api_?key|access_?key|private_?key|secret(?:_?key)?|token"
    r"|passw(?:or)?d|pwd)[ \t]*[:=][ \t]*(?![\"'<{$%])([^\s\"'#]{8,})")
REDACTED = "<REDACTED>"
MASK_REVEAL_FROM = 20
# [ \t], а не \s: с re.M «\s*» перескакивает через переводы строк, и файл из пустых строк разбирается квадратично
ENV_ASSIGNMENT = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=", re.M)
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)


@dataclass(frozen=True)
class SecretHit:
    path: str
    line: int
    kind: str
    masked: str


def is_secret_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name.startswith(".env.") and name.endswith(ENV_TEMPLATE_SUFFIXES):
        return False
    return (name in SECRET_FILE_NAMES or name.startswith(".env.") or name.endswith(".env")
            or PurePosixPath(name).suffix in SECRET_FILE_SUFFIXES)


def file_text(data: bytes) -> tuple[str, str]:
    """Текст файла и кодировка для обратной записи — одни и те же для поиска и для вымарывания.

    UTF-16 с BOM пишет pip freeze в PowerShell. Остальное читается как UTF-8 с surrogateescape: байты чужой
    кодировки (cp1251…) становятся «не буквами», как и при поиске, и после вымарывания возвращаются побайтно.
    """
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", "replace"), "utf-16"
    return data.decode("utf-8", "surrogateescape"), "utf-8"


def env_names(path: str, text: str) -> list[str]:
    """Имена переменных из файла .env (без значений) — их можно показать и передать коллеге."""
    name = PurePosixPath(path).name.lower()
    if not (name.startswith(".env") or name.endswith(".env")):
        return []
    return list(dict.fromkeys(ENV_ASSIGNMENT.findall(text)))


def _is_text(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name.startswith(".env") or PurePosixPath(name).suffix in TEXT_SUFFIXES


def _is_config(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name.startswith(".env") or PurePosixPath(name).suffix in CONFIG_SUFFIXES


def _mask(value: str) -> str:
    """Начало и конец — только у длинных значений: у короткого пароля 6 символов — это почти весь пароль."""
    return f"{value[:4]}…{value[-2:]}" if len(value) >= MASK_REVEAL_FROM else "…"


def _redact_match(match: re.Match) -> str:
    """Заменяет только само значение (группу), а не все его вхождения: в «password = 'password'» имя остаётся."""
    group = match.lastindex or 0
    start, end = match.start(group) - match.start(), match.end(group) - match.start()
    return f"{match.group(0)[:start]}{REDACTED}{match.group(0)[end:]}"


def _patterns(config: bool) -> list[tuple[str, re.Pattern]]:
    return [*PATTERNS, ("пароль/токен в конфиге", CONFIG_ASSIGNMENT)] if config else PATTERNS


def find_secrets(path: str, text: str) -> list[SecretHit]:
    if not _is_text(path):
        return []
    hits = []
    for number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in _patterns(_is_config(path)):
            match = pattern.search(line)
            if match and match.group(match.lastindex or 0) != REDACTED:
                hits.append(SecretHit(path, number, kind, _mask(match.group(match.lastindex or 0))))
                break
    return hits


def redact(text: str, config: bool = False) -> str:
    """Заменяет найденные значения на <REDACTED>, остальной текст не трогает."""
    text = PRIVATE_KEY_BLOCK.sub("<REDACTED PRIVATE KEY>", text)
    for _, pattern in _patterns(config):
        text = pattern.sub(_redact_match, text)
    return text


def redact_bytes(path: str, data: bytes) -> bytes:
    """redact() для файла целиком в его же кодировке; всё, кроме вымаранных значений, остаётся побайтно прежним."""
    text, encoding = file_text(data)
    return redact(text, _is_config(path)).encode(encoding, "surrogateescape")
