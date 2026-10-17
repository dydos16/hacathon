"""Эвристический поиск секретов: подсказка, а не полный аудит. Значения никогда не показываются целиком."""

import codecs
import json
import re
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import PurePosixPath

# Имена сравниваются без учёта регистра: .ENV в Windows — тот же .env
SECRET_FILE_NAMES = {".env", ".envrc", ".netrc", ".pgpass", ".pypirc", ".npmrc", ".git-credentials", ".dockercfg",
                     "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", "credentials.json",
                     "client_secret.json", "service_account.json", "secrets.toml",
                     "application_default_credentials.json"}  # gcloud auth application-default login
SECRET_FILE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore", ".jks", ".p8", ".ppk", ".tfvars",
                        ".tfstate", ".secrets"}  # состояние Terraform хранит пароли и ключи открытым текстом
# secrets.yaml, credentials.ini… — конфиги с секретами; secrets.py — модуль кода, его не трогаем
SECRET_STEMS = {"secrets", "credentials"}
SECRET_STEM_SUFFIXES = {"", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".txt", ".xml"}
# Файлы с общим именем, которые секретны по своему месту: ~/.kube/config, ~/.docker/config.json
SECRET_PLACES = {(".kube", "config"), (".docker", "config.json")}
# Копия «id_rsa.bak» — тот же ключ: суффиксы резервных копий снимаются перед проверкой имени
BACKUP_SUFFIXES = {".bak", ".old", ".orig", ".backup"}
# .env.example и подобные — шаблоны переменных для коллег: файл остаётся в пакете, но сканируется
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")
SNIFF_BYTES = 8192  # текст или двоичный файл — решаем по первым 8 КБ, не декодируя файл целиком
# В исходном коде значение без кавычек — выражение (password = get_password()): секрет там — только литерал.
# В остальном тексте (заметки, конфиги, скрипты оболочки, Dockerfile, логи) ищем и «password = abc».
# Кроме Python — языки, которые встречаются рядом с ним в научных проектах: Cython, C/C++, R, Julia, MATLAB…
CODE_SUFFIXES = {".py", ".pyw", ".pyi", ".ipynb", ".pyx", ".pxd", ".pxi", ".c", ".h", ".cc", ".cpp", ".hpp", ".cu",
                 ".f", ".f90", ".r", ".jl", ".m", ".js", ".ts", ".java", ".scala", ".go", ".rs"}
# Файл с таким расширением — текст, даже если в нём есть байт NUL: иначе один \x00 в начале конфига отключал
# для него поиск секретов. Двоичным по нулевым байтам считается только файл неизвестного вида (.npy, без расширения…)
TEXT_SUFFIXES = CODE_SUFFIXES | {".txt", ".csv", ".tsv", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".cfg",
                                 ".conf", ".cnf", ".properties", ".env", ".md", ".rst", ".tex", ".sh", ".bash",
                                 ".zsh", ".bat", ".cmd", ".ps1", ".xml", ".html", ".sql", ".log", ".j2", ".tf"}
UTF16_MIN_ZEROS = 0.25  # доля нулей в старших байтах: у текста UTF-16 их почти все, у текста с парой NUL — единицы
PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?"  # BLOCK — ключ PGP
                               r"(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S)
# Токены известного формата — на исходном тексте: регистр в них значим. Каждый шаблон начинается с литерала
# (sk-, AKIA, ://…), а границу слова проверяет lookbehind сразу за ним: так re ищет литерал быстрым поиском,
# а не пробует совпадение в каждой позиции, — CSV на десятки мегабайт сканируется за доли секунды, а не за минуту
TOKENS = [
    ("приватный ключ", PRIVATE_KEY_BLOCK),
    ("ключ AWS", re.compile(r"(A(?<!\wA)(?:KIA|SIA)[0-9A-Z]{16})\b")),  # ASIA — временный ключ STS
    ("токен GitHub", re.compile(r"(gh(?<!\wgh)[pousr]_[A-Za-z0-9]{30,})\b")),
    ("токен GitHub", re.compile(r"(github_pat_(?<!\wgithub_pat_)\w{30,})\b")),  # fine-grained
    ("ключ OpenAI/Anthropic", re.compile(r"(sk-(?<!\wsk-)(?:ant-)?[A-Za-z0-9_-]{20,})\b")),
    ("токен Slack", re.compile(r"(xox(?<!\wxox)[abposr]-[A-Za-z0-9-]{10,})\b")),
    ("токен Telegram-бота", re.compile(r":(?<=\d{8}:)([A-Za-z0-9_-]{35})\b")),  # номер бота перед «:» — не секрет
    ("ключ Google API", re.compile(r"(AIza(?<!\wAIza)[0-9A-Za-z_-]{35})(?![\w-])")),
    ("токен Hugging Face", re.compile(r"(hf_(?<!\whf_)[A-Za-z0-9]{30,})\b")),
    ("ключ Stripe", re.compile(r"(sk_live_(?<!\wsk_live_)[0-9A-Za-z]{20,})\b")),
    ("ключ Stripe", re.compile(r"(rk_live_(?<!\wrk_live_)[0-9A-Za-z]{20,})\b")),
    ("токен PyPI", re.compile(r"(pypi-(?<!\wpypi-)AgE[A-Za-z0-9_-]{50,})(?![\w-])")),
    ("ключ SendGrid", re.compile(r"(SG\.(?<!\wSG\.)[\w-]{16,}\.[\w-]{16,})")),
    # Начало токена — только после не-словесного символа: иначе на строке вида «eyJ-eyJ-…» перебор квадратичный
    ("токен JWT", re.compile(r"(eyJ(?<![\w-]eyJ)[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,})")),
    # scheme://user:пароль@host; подстановки ({password}, ${PW}, %(pw)s) и примеры из документации
    # (user:password@, xxx:xxx@) — не секрет
    ("пароль в адресе подключения", re.compile(
        r"://(?<=[\w+.-]://)[^\s:/@'\"\[]*:(?!(?i:x+|\*+|pass|passwd|password|pwd|secret)@)"
        r"((?:(?!%\()[^\s:/@'\"{}$<>])+)@")),
]
# Присваивания — на тексте в нижнем регистре (имена пишут как угодно: API_KEY, Api_Key), но без (?i): с ним re
# сравнивает каждый символ через lower() и работает в десять раз медленнее
# pass — отдельная часть имени (DB_PASS), но не compass. Проверка — после литерала, а не перед ним: каждая ветка
# начинается с буквы, и re перескакивает к возможным началам; ветка с lookbehind впереди замедляла поиск впятеро
PASSWORD = r"(?:passw(?:or)?d|pwd|pass(?<![a-z0-9]pass))"
KEYWORD = rf"(?:api_?key|access_?key|private_?key|secret(?:_?key)?|token|{PASSWORD[3:-1]})"
ASSIGNMENTS = [
    # pip: --index-url https://ТОКЕН@host — у частных индексов токен часто стоит вместо имени пользователя
    *(("токен в адресе индекса пакетов", re.compile(rf"{option}[ \t=]+[a-z][a-z0-9+.-]{{0,30}}://([^\s/@'\"]+)@"))
      for option in ("index-url", "find-links")),
    # Имя переменной должно заканчиваться ключевым словом: API_KEY, db_password — да, tokenizer, max_tokens — нет.
    # Кавычка может быть экранирована (\"…\" внутри JSON ноутбука). Заглушки — не значения: <…>, {{шаблон}},
    # ${VAR}, %(x)s, ********, your-api-key
    ("пароль/токен в коде", re.compile(
        KEYWORD + r"""\b\\?["']?[ \t]*[:=][ \t]*\\?["'](?![<{$%*]|your)([^"'\s\\]{8,})\\?["']""")),
    # Пароль бывает коротким («hunter2») и с пробелами («correct horse battery»); у токенов и ключей порог прежний —
    # иначе в NLP-коде вымарывались бы unk_token = "unknown" и подобные
    ("пароль в коде", re.compile(
        PASSWORD + r"""\b\\?["']?[ \t]*[:=][ \t]*\\?["'](?![<{$%*]|your)([^"'\s\\][^"'\\\n]{5,}?)\\?["']""")),
    # Строка подключения Azure: «…;AccountKey=base64==;…», Service Bus — SharedAccessKey. По шаблону на имя:
    # литерал в начале — быстрый поиск (см. TOKENS)
    *(("ключ Azure", re.compile(rf"{name}=([^;\"'\s]{{16,}})")) for name in ("accountkey", "sharedaccesskey")),
    # kubeconfig: закрытый ключ клиента в base64 без кавычек — в том числе в .yaml рядом с кодом
    ("ключ из kubeconfig", re.compile(r"client-key-data[ \t]*:[ \t]*[\"']?([a-z0-9+/=]{16,})")),
]
# То же присваивание без кавычек — везде, кроме кода: «password = abc», «export TOKEN=abc», «ENV DB_PASSWORD=abc»,
# «- DB_PASSWORD=abc» (compose), «set API_KEY=abc» (bat), «$env:TOKEN=abc». Значение занимает остаток строки
# (можно с комментарием): «token: Authentication token for the API» — описание, а не секрет; «your-key-here»,
# «********», <…>, ${…}, %(…)s — заглушки; со скобкой — вызов функции из примера кода. Для текста в нижнем регистре
PLAIN_ASSIGNMENT = re.compile(
    r"(?m)^[ \t]*(?:(?:export|env|arg|set|-)[ \t]+|\$env:)?[\"']?[\w./:@-]{0,80}?" + KEYWORD +
    r"[\"']?[ \t]*[:=][ \t]*(?![\"'<{$%*]|your)([^\s\"'#(]{6,})[\"']?[ \t]*(?:[#;][^\n]*|\r)?$")
# Ключ из соседних литералов: "sk-ant-api03-" "EXAMPLE…" — Python склеит их в одну строку, в том числе через перенос.
# По шаблону на каждое начало ключа: литерал в начале шаблона — быстрый поиск (см. TOKENS)
LITERAL_JOIN = re.compile(r"""\\?["'][ \t]*(?:\\?\r?\n[ \t]*)?\\?["']""")
SPLIT_KEYS = [re.compile(rf"{prefix}(?<!\w{prefix})[\w-]*(?:{LITERAL_JOIN.pattern}[\w-]+)+")
              for prefix in ("sk", "rk_", "gh", "github_pat_", "hf_", "xox", "AKIA", "ASIA", "AIza", "pypi-")]
# Те же шаблоны токенов для байтов двоичного файла: все шаблоны — ASCII, \w в байтах — только латиница и цифры
BINARY_TOKENS = [(kind, re.compile(pattern.pattern.encode(), pattern.flags & ~re.UNICODE)) for kind, pattern in TOKENS]
IN_BINARY = " в двоичном файле"
REDACTED = "<REDACTED>"
MASK = "…"  # значение не показываем даже частично: часть пароля тоже секрет
# [ \t], а не \s: с re.M «\s*» перескакивает через переводы строк, и файл из пустых строк разбирается квадратично.
# «=» не должен быть частью base64-строки ключа: «ABC==» — не присваивание. Значение в кавычках может занимать
# несколько строк (ключ PEM, JSON) — оно пропускается целиком, и его строки не становятся «переменными»
ENV_ASSIGNMENT = re.compile(r"""^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=(?!=)[ \t]*"""
                            r"""(?:"(?:[^"\\]|\\[\s\S])*(?:"|\Z)|'[^']*(?:'|\Z))?""", re.M)
# Управляющие символы в «тексте» UTF-16 без BOM: так выглядят двоичные данные (int16 и т. п.), а не текст
NOT_TEXT = re.compile("[\x00-\x08\x0e-\x1f\ufffd]")


@dataclass(frozen=True)
class SecretHit:
    path: str
    line: int
    kind: str
    masked: str


def _secret_name(path: str) -> str:
    """Имя файла без регистра и без суффиксов копии: «Id_RSA.bak» — то же, что «id_rsa»."""
    stem = PurePosixPath(PurePosixPath(path).name.lower())
    while stem.suffix in BACKUP_SUFFIXES:
        stem = stem.with_suffix("")
    return stem.name


def is_secret_file(path: str) -> bool:
    name = _secret_name(path)
    if name.startswith(".env.") and name.endswith(ENV_TEMPLATE_SUFFIXES):
        return False
    stem, suffix = PurePosixPath(name).stem, PurePosixPath(name).suffix
    return (name in SECRET_FILE_NAMES or name.startswith(".env.") or name.endswith(".env")
            or suffix in SECRET_FILE_SUFFIXES or (stem in SECRET_STEMS and suffix in SECRET_STEM_SUFFIXES)
            or tuple(PurePosixPath(path.lower()).parts[-2:]) in SECRET_PLACES)


def _known_text(path: str) -> bool:
    """Расширение текстового файла или dot-файл конфигурации (.env, .npmrc): такой файл — текст при любых байтах."""
    name = _secret_name(path)
    return name.startswith(".") or PurePosixPath(name).suffix in TEXT_SUFFIXES


def file_text(data: bytes, path: str = "") -> tuple[str, str] | None:
    """Текст файла и кодировка для обратной записи — одни и те же для поиска и для вымарывания; None — двоичный файл.

    Решение — по первым 8 КБ, файл целиком не декодируется: NUL в тексте бывает только в UTF-16. UTF-16 с BOM пишет
    pip freeze в PowerShell, без BOM — его нули стоят через байт. Остальное читается как UTF-8 (BOM снимается и
    возвращается) с surrogateescape: байты чужой кодировки (cp1251…) становятся «не буквами», как и при поиске,
    и после вымарывания возвращаются побайтно.
    """
    head = data[:SNIFF_BYTES]
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", "replace"), "utf-16"
    if b"\0" in head:
        if encoding := _utf16_without_bom(head):
            return data.decode(encoding, "replace"), encoding
        if not _known_text(path):
            return None
    encoding = "utf-8-sig" if head.startswith(codecs.BOM_UTF8) else "utf-8"
    return data.decode(encoding, "surrogateescape"), encoding


def _utf16_without_bom(head: bytes) -> str | None:
    """Кодировка UTF-16 без BOM: нули только в старших байтах, а начало файла читается как печатный текст."""
    for encoding, low_bytes, high_bytes in (("utf-16-le", head[0::2], head[1::2]), ("utf-16-be", head[1::2], head[0::2])):
        if b"\0" not in low_bytes and high_bytes.count(0) >= UTF16_MIN_ZEROS * len(high_bytes):
            sample = codecs.getincrementaldecoder(encoding)("replace").decode(head)
            return None if NOT_TEXT.search(sample) else encoding
    return None


def read_text(data: bytes, path: str = "") -> str:
    """Текст файла для поиска секретов и имён переменных; у двоичного файла текста нет."""
    decoded = file_text(data, path)
    return decoded[0] if decoded else ""


def env_names(path: str, text: str) -> list[str]:
    """Имена переменных из файла .env (без значений) — их можно показать и передать коллеге."""
    name = PurePosixPath(path).name.lower()
    if not (name.startswith(".env") or name.endswith(".env")):
        return []
    text = PRIVATE_KEY_BLOCK.sub("", text)  # строки тела ключа без кавычек — не переменные
    return list(dict.fromkeys(ENV_ASSIGNMENT.findall(text)))


def _plain(path: str) -> bool:
    """Значение без кавычек — секрет везде, кроме исходного кода (и его копий .bak): там это выражение."""
    return PurePosixPath(_secret_name(path)).suffix not in CODE_SUFFIXES


def _key_kind(pieces: str) -> str:
    """Вид ключа, если склеенные литералы дают токен известного формата; иначе пусто — склейка не трогается."""
    joined = LITERAL_JOIN.sub("", pieces)
    return next((kind for kind, pattern in TOKENS if pattern.search(joined)), "")


def _printed(output: dict) -> str:
    """Текст, который ячейка напечатала: stdout, результат, трассировка ошибки."""
    chunks = [output.get("text", ""), output.get("data", {}).get("text/plain", ""), *output.get("traceback", [])]
    return "\n".join(chunk if isinstance(chunk, str) else "\n".join(chunk) for chunk in chunks)


def _notebook_values(text: str) -> set[str]:
    """Значения без кавычек из вывода ячеек ноутбука («token=abc…» в stdout) — так, как они записаны в JSON файла."""
    try:
        printed = "\n".join(_printed(output) for cell in json.loads(text)["cells"]
                            for output in cell.get("outputs", []))
    except (ValueError, LookupError, TypeError, AttributeError, RecursionError):
        return set()  # не JSON ноутбука: остальные шаблоны ищут по тексту файла как есть
    return {json.dumps(printed[match.start(1):match.end(1)], ensure_ascii=ascii_only)[1:-1]
            for match in PLAIN_ASSIGNMENT.finditer(_lower(printed)) for ascii_only in (True, False)}


def _lower(text: str) -> str:
    """Текст в нижнем регистре той же длины: позиции совпадений в нём — позиции в исходном тексте.

    Из всех символов только «İ» в нижнем регистре даёт два символа — его заменяем заранее.
    """
    return text.replace("\u0130", "i").lower()


def _spans(text: str, plain: bool, notebook: bool = False) -> list[tuple[int, int, str]]:
    """Где в тексте значения секретов: (начало, конец, вид) в порядке шаблонов; уже вымаранные — не находка."""
    # NUL — разрыв строки для поиска: «\0\0API_TOKEN=…» иначе не начинало бы строку присваивания. Замена символа на
    # символ: позиции находок остаются позициями в исходном тексте
    searched = text.replace("\0", "\n") if "\0" in text else text  # копия — только когда NUL есть
    lowered = _lower(searched)
    searches = [(pattern, searched, kind) for kind, pattern in TOKENS]
    searches += [(pattern, lowered, kind) for kind, pattern in ASSIGNMENTS]
    searches += [(PLAIN_ASSIGNMENT, lowered, "пароль/токен без кавычек")] if plain else []
    spans = [(match.start(match.lastindex or 0), match.end(match.lastindex or 0), kind)
             for pattern, target, kind in searches for match in pattern.finditer(target)]
    spans += [(match.start(), match.end(), kind) for pattern in SPLIT_KEYS for match in pattern.finditer(text)
              if (kind := _key_kind(match.group()))]
    for value in _notebook_values(text) if notebook else ():
        # Значение не нашлось в файле (JSON записан с другим экранированием) — находка всё равно есть: вымарать её
        # не выйдет, и проверка после вымарывания остановит сборку
        found = [match.span() for match in re.finditer(re.escape(value), text)] or [(0, 0)]
        spans += [(start, end, "пароль/токен в выводе ячейки") for start, end in found]
    return [span for span in spans if text[span[0]:span[1]] != REDACTED]


def _is_notebook(path: str) -> bool:
    return path.lower().endswith(".ipynb")


def find_secrets(path: str, text: str) -> list[SecretHit]:
    """Все совпадения во всём тексте; в отчёт — одна находка на строку, вид — по первому подходящему шаблону."""
    spans = _spans(text, _plain(path), _is_notebook(path))
    if not spans:
        return []
    return _hits(path, [match.start() for match in re.finditer("\n", text)], spans)


def _hits(path: str, breaks: list[int], spans: list[tuple[int, int, str]]) -> list[SecretHit]:
    lines: dict[int, str] = {}
    for start, _, kind in spans:
        lines.setdefault(bisect_left(breaks, start) + 1, kind)
    return [SecretHit(path, line, kind, MASK) for line, kind in sorted(lines.items())]


def scan(path: str, data: bytes) -> list[SecretHit]:
    """Секреты в файле. В двоичном файле (pickle, база SQLite, .npz…) — токены известного формата, по байтам, без
    декодирования целиком: вымарать их там нельзя, поэтому находка останавливает сборку, а не уходит в пакет молча."""
    decoded = file_text(data, path)
    if decoded is not None:
        return find_secrets(path, decoded[0])
    spans = [(match.start(match.lastindex or 0), match.end(match.lastindex or 0), kind + IN_BINARY)
             for kind, pattern in BINARY_TOKENS for match in pattern.finditer(data)]
    return _hits(path, [match.start() for match in re.finditer(b"\n", data)], spans) if spans else []


def _splice(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Каждый найденный участок — один <REDACTED>; пересекающиеся находки (ключ внутри присваивания) сливаются."""
    pieces, cursor = [], 0
    for start, end, _ in sorted(span for span in spans if span[1] > span[0]):
        if start >= cursor:
            pieces += [text[cursor:start], REDACTED]
        cursor = max(cursor, end)
    return "".join(pieces) + text[cursor:]


def redact(text: str, plain: bool = False) -> str:
    """Заменяет все найденные значения на <REDACTED>, остальной текст не трогает; plain — ещё и значения без кавычек.

    Заменяется только само значение, а не все его вхождения: в «password = 'password'» имя остаётся. Ключ из
    соседних литералов заменяется целиком, вместе с кавычками между частями: остаётся один литерал.
    """
    return _splice(text, _spans(text, plain))


def redact_bytes(path: str, data: bytes) -> bytes:
    """redact() для файла целиком в его же кодировке; двоичный файл и файл без секретов возвращаются как есть."""
    decoded = file_text(data, path)
    if decoded is None:
        return data
    text, encoding = decoded
    cleaned = _splice(text, _spans(text, _plain(path), _is_notebook(path)))
    return data if cleaned == text else cleaned.encode(encoding, "surrogateescape")
