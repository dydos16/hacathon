"""Приём загрузки: .py/.ipynb-файлы или ZIP-архив → словарь {путь: байты}.

Всё читается в память, на диск ничего не распаковывается и не выполняется.
"""

import io
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_UNPACKED_BYTES = 100 * 1024 * 1024
MAX_FILES = 2000
JUNK_PARTS = {
    "__pycache__", ".git", ".hg", ".svn", ".venv", "venv", "env", ".idea", ".vscode",
    ".ipynb_checkpoints", ".pytest_cache", ".mypy_cache", "node_modules", "__MACOSX",
}
JUNK_SUFFIXES = {".pyc", ".pyo"}
JUNK_NAMES = {".DS_Store", "Thumbs.db"}
APPLE_DOUBLE_PREFIX = "._"  # метаданные macOS рядом с файлом, на внешних дисках и в tar
ENCRYPTED_FLAG = 0x1
UTF8_FLAG = 0x800
# Что бросает zipfile на повреждённых данных, неподдерживаемом сжатии или пароле
ZIP_READ_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError)


class IntakeError(ValueError):
    """Загрузку нельзя принять (небезопасный путь, превышен лимит, неверный формат)."""


def _safe_path(raw: str) -> str | None:
    """Нормализует путь из архива; None — служебный файл; IntakeError — попытка выйти из папки.

    Буквы приводятся к NFC: macOS хранит «й» и «ё» разложенными, и без этого «данные_й.csv» из архива
    не совпало бы с тем же именем в коде."""
    if any(ord(ch) < 32 for ch in raw):
        raise IntakeError(f"Управляющие символы в имени файла: {raw!r}")
    path = PurePosixPath(unicodedata.normalize("NFC", raw).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
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


def _strip_common_root(files: dict[str, bytes]) -> dict[str, bytes]:
    """Архив «project/…» превращается в «…», чтобы пути были от корня проекта."""
    tops = {p.split("/", 1)[0] for p in files}
    if len(tops) == 1 and all("/" in p for p in files):
        return {p.split("/", 1)[1]: data for p, data in files.items()}
    return files


def read_zip(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise IntakeError(f"Архив больше {MAX_ARCHIVE_BYTES // 1024 // 1024} МБ")
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
    return _strip_common_root({path: _read_entry(archive, info) for path, info in entries})


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.flag_bits & ENCRYPTED_FLAG:
        raise IntakeError("Архив защищён паролем — загрузите его без пароля")
    try:
        return archive.read(info)
    except ZIP_READ_ERRORS as exc:
        raise IntakeError(f"Не удалось распаковать {info.filename!r}: архив повреждён "
                          "или сжат неподдерживаемым методом") from exc


def _merge(files: dict[str, bytes], added: dict[str, bytes]) -> dict[str, bytes]:
    """Добавляет файлы очередной загрузки: одноимённый файл с другим содержимым молча не затирается,
    а лимиты действуют на всю загрузку, а не на каждый файл по отдельности."""
    clash = next((p for p, data in added.items() if files.get(p, data) != data), None)
    if clash:
        raise IntakeError(f"Файл «{clash}» загружен дважды с разным содержимым — оставьте один вариант")
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


def read_directory(root: Path) -> dict[str, bytes]:
    """Для CLI и демо-проектов: читает папку с теми же фильтрами и лимитами, что и архив.

    Лимиты проверяются по ходу чтения, чтобы случайно указанная огромная папка не попала в память целиком.
    """
    files, total = {}, 0
    for file in sorted(root.rglob("*")):
        path = _safe_path(file.relative_to(root).as_posix())
        if path is None or not file.is_file():
            continue
        files[path] = file.read_bytes()
        total += len(files[path])
        if len(files) > MAX_FILES or total > MAX_UNPACKED_BYTES:
            raise IntakeError(f"Папка слишком большая: больше {MAX_FILES} файлов "
                              f"или {MAX_UNPACKED_BYTES // 1024 // 1024} МБ")
    return files
