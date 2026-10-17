"""Приём загрузки: .py/.ipynb-файлы или ZIP-архив → словарь {путь: байты}.

Всё читается в память, на диск ничего не распаковывается и не выполняется.
"""

import io
import stat
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
# Каждая запись каталога начинается с этой сигнатуры: их число в байтах архива — верхняя граница записей,
# которые создаст zipfile. Число из конца архива не годится: zipfile читает каталог по размеру, а не по нему.
CENTRAL_DIR_SIGNATURE = b"PK\x01\x02"
# Управляющие (Cc), невидимые и смена направления текста (Cf: U+200B, U+FEFF, U+202E), разрывы строк (Zl, Zp)
HIDDEN_CATEGORIES = {"Cc", "Cf", "Zl", "Zp"}
# Имена устройств Windows: с любым расширением и в любом регистре такой файл там не создать
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"{port}{n}" for port in ("COM", "LPT") for n in "0123456789¹²³")}
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
# Что бросает zipfile на повреждённых данных, неподдерживаемом сжатии или пароле; ValueError (в том числе
# UnicodeDecodeError) и OverflowError — на испорченных смещениях и именах
ZIP_READ_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, ValueError,
                   OverflowError)


class IntakeError(Exception):
    """Загрузку нельзя принять (небезопасный путь, превышен лимит, неверный формат).

    Не ValueError: ошибки zipfile ловятся как ValueError, и своя ошибка не должна теряться среди них."""


def _safe_path(raw: str) -> str | None:
    """Нормализует путь из архива; None — служебный файл; IntakeError — попытка выйти из папки.

    Буквы приводятся к NFC: macOS хранит «й» и «ё» разложенными, и без этого «данные_й.csv» из архива
    не совпало бы с тем же именем в коде."""
    # Невидимые символы: «x\u202eyp.txt» выглядит как «xtxt.py», «a\u200b.py» — как «a.py»
    if any(unicodedata.category(ch) in HIDDEN_CATEGORIES for ch in raw):
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
    if any(part.split(".")[0].rstrip(" ").upper() in WINDOWS_RESERVED for part in path.parts):
        raise IntakeError(f"Имя зарезервировано в Windows (CON, NUL, COM1…), там такой файл не создать: {raw!r}")
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
    if data.count(CENTRAL_DIR_SIGNATURE) > MAX_ZIP_RECORDS:  # до того, как zipfile создаст объект на каждую
        raise IntakeError(f"В архиве больше {MAX_ZIP_RECORDS} записей, включая служебные (.git, .venv): "
                          "уберите их из архива")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except ZIP_READ_ERRORS as exc:
        raise IntakeError("Файл не является корректным ZIP-архивом или повреждён") from exc
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
    if stat.S_ISLNK(info.external_attr >> 16):  # распаковщик создал бы ссылку, например, на ~/.ssh
        raise IntakeError(f"{info.filename!r} в архиве — символическая ссылка: положите в архив сам файл")
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
    _check_totals(len(merged), sum(map(len, merged.values())))
    return merged


def _check_totals(count: int, size: int) -> None:
    if count > MAX_FILES or size > MAX_UNPACKED_BYTES:
        raise IntakeError(f"Загрузка слишком большая: больше {MAX_FILES} файлов "
                          f"или {MAX_UNPACKED_BYTES // 1024 // 1024} МБ в сумме")


def _is_zip(name: str, keep_paths: bool) -> bool:
    return name.lower().endswith(".zip") and not keep_paths


def _upload_path(name: str, keep_paths: bool) -> str | None:
    return _safe_path(name if keep_paths else PurePosixPath(name.replace("\\", "/")).name)


def check_upload(uploads: list[tuple[str, int]], keep_paths: bool = False) -> None:
    """Число и размер загрузки — по именам и размерам, до чтения байтов. Служебные файлы (.git, .venv)
    не считаются, как и в read_upload."""
    sizes = [size for name, size in uploads if _is_zip(name, keep_paths) or _upload_path(name, keep_paths)]
    _check_totals(len(sizes), sum(sizes))


def read_upload(uploads: list[tuple[str, bytes]], keep_paths: bool = False) -> dict[str, bytes]:
    """Принимает список (имя, содержимое): ZIP раскрывается, остальные файлы кладутся в корень.

    keep_paths — загружена папка целиком: имя — путь внутри неё («proj/lib/x.py»), подпапки сохраняются,
    общая папка верхнего уровня срезается, а ZIP внутри папки остаётся обычным файлом."""
    files: dict[str, bytes] = {}
    for name, data in uploads:
        if _is_zip(name, keep_paths):
            files = _merge(files, read_zip(data))
        elif (path := _upload_path(name, keep_paths)) is not None:
            files = _merge(files, {path: data})
    if keep_paths:
        files = _strip_common_root(files)
    if not any(p.endswith((".py", ".ipynb")) for p in files):
        raise IntakeError("Не найдено ни одного файла .py или .ipynb")
    return files


def read_directory(root: Path) -> dict[str, bytes]:
    """Для CLI и демо-проектов: читает папку с теми же фильтрами и лимитами, что и архив.

    Ссылки (например, на ~/.netrc) и FIFO не читаются: первые ведут из проекта, вторые читались бы вечно.
    Размер берётся из lstat до чтения, чтобы случайно указанная огромная папка не попала в память целиком.
    rglob не заходит в ссылки на папки, поэтому проверки самого файла достаточно.
    """
    files, total = {}, 0
    for file in sorted(root.rglob("*")):
        path = _safe_path(file.relative_to(root).as_posix())
        if path is None or not stat.S_ISREG((info := file.lstat()).st_mode):
            continue
        total += info.st_size
        if len(files) >= MAX_FILES or total > MAX_UNPACKED_BYTES:
            raise IntakeError(f"Папка слишком большая: больше {MAX_FILES} файлов "
                              f"или {MAX_UNPACKED_BYTES // 1024 // 1024} МБ")
        files[path] = file.read_bytes()
    return files


def read_file(file: Path) -> dict[str, bytes]:
    """Для CLI: один файл или ZIP. Тип и размер проверяются до чтения: FIFO или /dev/zero читались бы вечно."""
    info = file.stat()
    if not stat.S_ISREG(info.st_mode):
        raise IntakeError(f"«{file}» — не обычный файл и не папка")
    if info.st_size > MAX_ARCHIVE_BYTES:
        raise IntakeError(f"Файл больше {MAX_ARCHIVE_BYTES // 1024 // 1024} МБ")
    return read_upload([(file.name, file.read_bytes())])
