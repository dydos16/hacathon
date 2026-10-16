"""Приём загрузки: .py/.ipynb-файлы или ZIP-архив → словарь {путь: байты}.

Всё читается в память, на диск ничего не распаковывается и не выполняется.
"""

import io
import struct
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 150 * 1024 * 1024  # = maxUploadSize в .streamlit/config.toml: проект вместе с примером данных
MAX_UNPACKED_BYTES = 600 * 1024 * 1024  # в 4 раза больше архива (CSV сжимается в разы), но не zip-бомба
MAX_FILES = 2000
# Записи центрального каталога, включая служебные: каждая становится объектом в памяти ещё до фильтрации.
# ponytail: потолок ~ десятки МБ памяти на запрос; при большем — потоковый разбор каталога
MAX_ZIP_RECORDS = 50_000
EOCD_SIGNATURE = b"PK\x05\x06"  # конец центрального каталога ZIP
EOCD_SIZE = 22
MAX_ZIP_COMMENT = 0xFFFF
ENTRY_COUNT_OFFSET = 10  # число записей в конце каталога: 2 байта, смещение от сигнатуры
ENTRY_COUNT = struct.Struct("<H")
INVISIBLE_CHARS = set("\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
JUNK_PARTS = {
    "__pycache__", ".git", ".hg", ".svn", ".venv", "venv", "env", ".idea", ".vscode",
    ".ipynb_checkpoints", ".pytest_cache", ".mypy_cache", "node_modules", "__MACOSX",
}
JUNK_SUFFIXES = {".pyc", ".pyo"}
JUNK_NAMES = {".DS_Store", "Thumbs.db"}
APPLE_DOUBLE_PREFIX = "._"  # метаданные macOS рядом с файлом, на внешних дисках и в tar
ENCRYPTED_FLAG = 0x1
# Только методы, у которых степень сжатия ограничена: bzip2 и lzma сжимают нули в тысячи раз
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
READ_CHUNK_BYTES = 1024 * 1024
UTF8_FLAG = 0x800
# Что бросает zipfile на повреждённых данных, неподдерживаемом сжатии или пароле
ZIP_READ_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError)


class IntakeError(ValueError):
    """Загрузку нельзя принять (небезопасный путь, превышен лимит, неверный формат)."""


def _safe_path(raw: str) -> str | None:
    """Нормализует путь из архива; None — служебный файл; IntakeError — попытка выйти из папки.

    Буквы приводятся к NFC: macOS хранит «й» и «ё» разложенными, и без этого «данные_й.csv» из архива
    не совпало бы с тем же именем в коде."""
    # Управляющие и невидимые символы смены направления текста: «x\u202eyp.txt» выглядит как «xtxt.py»
    if any(ord(ch) < 32 or 0x7f <= ord(ch) <= 0x9f or ch in INVISIBLE_CHARS for ch in raw):
        raise IntakeError(f"Управляющие или невидимые символы в имени файла: {raw!r}")
    path = PurePosixPath(unicodedata.normalize("NFC", raw).replace("\\", "/"))
    # «:» в любой части пути — на Windows это поток NTFS («a/C:evil.py»); точку и пробел в конце Windows отрезает
    if (path.is_absolute() or ".." in path.parts or any(":" in part for part in path.parts)
            or any(part.endswith((".", " ")) for part in path.parts if part != ".")):
        raise IntakeError(f"Небезопасный путь в архиве: {raw!r}")
    if not path.parts or any(p in JUNK_PARTS for p in path.parts):
        return None
    if path.name in JUNK_NAMES or path.suffix in JUNK_SUFFIXES or path.name.startswith(APPLE_DOUBLE_PREFIX):
        return None
    return str(path)


def _entry_name(info: zipfile.ZipInfo) -> str:
    """Имя файла в архиве. Без флага UTF-8 zipfile читает имя как cp437, но Проводник Windows пишет
    кириллицу в cp866, а многие архиваторы — в UTF-8 без флага."""
    if info.flag_bits & UTF8_FLAG:
        return info.filename
    raw = info.filename.encode("cp437")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp866")


def _declared_record_count(data: bytes) -> int | None:
    """Число записей из конца архива: проверяется до того, как zipfile создаст объект на каждую запись."""
    start = data.rfind(EOCD_SIGNATURE, max(0, len(data) - EOCD_SIZE - MAX_ZIP_COMMENT))
    if start < 0 or start + EOCD_SIZE > len(data):
        return None
    return ENTRY_COUNT.unpack_from(data, start + ENTRY_COUNT_OFFSET)[0]


def _check_unique(paths: list[str]) -> None:
    """Пути, совпадающие без учёта регистра, на macOS и Windows — один файл: лучше ошибка, чем тихая подмена."""
    seen: dict[str, str] = {}
    for path in paths:
        key = path.casefold()
        if key in seen:
            if seen[key] == path:
                raise IntakeError(f"В архиве несколько записей с именем «{path}»")
            raise IntakeError(f"«{seen[key]}» и «{path}» отличаются только регистром — на macOS и Windows "
                              "это один файл, оставьте один вариант")
        seen[key] = path


def _strip_common_root(files: dict[str, bytes]) -> dict[str, bytes]:
    """Архив «project/…» превращается в «…», чтобы пути были от корня проекта."""
    tops = {p.split("/", 1)[0] for p in files}
    if len(tops) == 1 and all("/" in p for p in files):
        return {p.split("/", 1)[1]: data for p, data in files.items()}
    return files


def read_zip(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise IntakeError(f"Архив больше {MAX_ARCHIVE_BYTES // 1024 // 1024} МБ")
    declared = _declared_record_count(data)
    if declared is not None and declared > MAX_ZIP_RECORDS:
        raise IntakeError(f"В архиве больше {MAX_ZIP_RECORDS} записей, включая служебные (.git, .venv): "
                          "уберите их из архива")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IntakeError("Файл не является корректным ZIP-архивом") from exc
    # Служебные файлы (.git, .venv, __pycache__) не распаковываются и не считаются в лимиты:
    # проект с историей git не должен упираться в лимит числа файлов
    entries = [(path, info) for info in archive.infolist() if not info.is_dir()
               if (path := _safe_path(_entry_name(info))) is not None]
    if len(entries) > MAX_FILES:
        raise IntakeError(f"В архиве больше {MAX_FILES} файлов")
    if sum(info.file_size for _, info in entries) > MAX_UNPACKED_BYTES:
        raise IntakeError("Распакованный архив слишком большой (возможна zip-бомба)")
    _check_unique([path for path, _ in entries])
    files: dict[str, bytes] = {}
    budget = MAX_UNPACKED_BYTES
    for path, info in entries:
        files[path] = _read_entry(archive, info, budget)
        budget -= len(files[path])
    return _strip_common_root(files)


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo, budget: int) -> bytes:
    if info.flag_bits & ENCRYPTED_FLAG:
        raise IntakeError("Архив защищён паролем — загрузите его без пароля")
    if info.compress_type not in ALLOWED_COMPRESSION:
        raise IntakeError(f"Не удалось распаковать {info.filename!r}: сжат неподдерживаемым методом — пересоздайте архив обычным ZIP")
    try:
        with archive.open(info) as stream:
            return _read_limited(stream, budget)
    except ZIP_READ_ERRORS as exc:
        raise IntakeError(f"Не удалось распаковать {info.filename!r}: архив повреждён") from exc


def _read_limited(stream, limit: int) -> bytes:
    """Читает по частям и считает реальные байты: заголовок архива может соврать о размере."""
    chunks, total = [], 0
    while chunk := stream.read(READ_CHUNK_BYTES):
        total += len(chunk)
        if total > limit:
            raise IntakeError("Распакованный архив слишком большой (возможна zip-бомба)")
        chunks.append(chunk)
    return b"".join(chunks)


def _merge(files: dict[str, bytes], added: dict[str, bytes]) -> dict[str, bytes]:
    """Добавляет файлы очередной загрузки: одноимённый файл с другим содержимым молча не затирается,
    а лимиты действуют на всю загрузку, а не на каждый файл по отдельности."""
    clash = next((p for p, data in added.items() if files.get(p, data) != data), None)
    if clash:
        raise IntakeError(f"Файл «{clash}» загружен дважды с разным содержимым — оставьте один вариант")
    _check_unique([*files, *(p for p in added if p not in files)])
    merged = {**files, **added}
    if len(merged) > MAX_FILES or sum(map(len, merged.values())) > MAX_UNPACKED_BYTES:
        raise IntakeError(f"Загрузка слишком большая: больше {MAX_FILES} файлов "
                          f"или {MAX_UNPACKED_BYTES // 1024 // 1024} МБ в сумме")
    return merged


def read_upload(uploads: list[tuple[str, bytes]], keep_paths: bool = False) -> dict[str, bytes]:
    """Принимает список (имя, содержимое): ZIP раскрывается, остальные файлы кладутся в корень.

    keep_paths — загружена папка целиком: имя — путь внутри неё («proj/lib/x.py»), подпапки сохраняются,
    общая папка верхнего уровня срезается, а ZIP внутри папки остаётся обычным файлом."""
    files: dict[str, bytes] = {}
    for name, data in uploads:
        if name.lower().endswith(".zip") and not keep_paths:
            files = _merge(files, read_zip(data))
            continue
        path = _safe_path(name if keep_paths else PurePosixPath(name.replace("\\", "/")).name)
        if path is not None:
            files = _merge(files, {path: data})
    if keep_paths:
        files = _strip_common_root(files)
    if not any(p.endswith((".py", ".ipynb")) for p in files):
        raise IntakeError("Не найдено ни одного файла .py или .ipynb")
    return files


def _stays_inside(file: Path, root: Path) -> bool:
    """Ссылка из папки на файл вне неё (например, ~/.aws/credentials) — не часть проекта и не читается."""
    return file.resolve().is_relative_to(root)


def read_directory(root: Path) -> dict[str, bytes]:
    """Для CLI и демо-проектов: читает папку с теми же фильтрами и лимитами, что и архив.

    Лимиты проверяются по ходу чтения, чтобы случайно указанная огромная папка не попала в память целиком.
    """
    files, total = {}, 0
    real_root = root.resolve()
    for file in sorted(root.rglob("*")):
        path = _safe_path(file.relative_to(root).as_posix())
        if path is None or not _stays_inside(file, real_root) or not file.is_file():
            continue
        files[path] = file.read_bytes()
        total += len(files[path])
        if len(files) > MAX_FILES or total > MAX_UNPACKED_BYTES:
            raise IntakeError(f"Папка слишком большая: больше {MAX_FILES} файлов "
                              f"или {MAX_UNPACKED_BYTES // 1024 // 1024} МБ")
    return files
