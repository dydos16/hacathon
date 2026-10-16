"""Приём загрузки: .py/.ipynb-файлы или ZIP-архив → словарь {путь: байты}.

Всё читается в память, на диск ничего не распаковывается и не выполняется.
"""

import io
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_UNPACKED_BYTES = 100 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_FILES = 2000
JUNK_PARTS = {
    "__pycache__", ".git", ".hg", ".svn", ".venv", "venv", "env", ".idea", ".vscode",
    ".ipynb_checkpoints", ".pytest_cache", ".mypy_cache", "node_modules", "__MACOSX",
}
JUNK_SUFFIXES = {".pyc", ".pyo"}
JUNK_NAMES = {".DS_Store", "Thumbs.db"}


class IntakeError(ValueError):
    """Загрузку нельзя принять (небезопасный путь, превышен лимит, неверный формат)."""


def _safe_path(raw: str) -> str | None:
    """Нормализует путь из архива; None — служебный файл; IntakeError — попытка выйти из папки."""
    if any(c in raw for c in "\x00\r\n"):
        raise IntakeError(f"Недопустимые символы в имени файла: {raw!r}")
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
        raise IntakeError(f"Небезопасный путь в архиве: {raw!r}")
    if not path.parts or any(p in JUNK_PARTS for p in path.parts):
        return None
    if path.name in JUNK_NAMES or path.suffix in JUNK_SUFFIXES:
        return None
    return str(path)


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
    entries = [i for i in archive.infolist() if not i.is_dir()]
    if len(entries) > MAX_FILES:
        raise IntakeError(f"В архиве больше {MAX_FILES} файлов")
    if sum(i.file_size for i in entries) > MAX_UNPACKED_BYTES:
        raise IntakeError("Распакованный архив слишком большой (возможна zip-бомба)")
    for info in entries:
        if info.file_size > MAX_FILE_BYTES:
            raise IntakeError(f"Файл {info.filename!r} больше {MAX_FILE_BYTES // 1024 // 1024} МБ")
        # compress_size == 0 бывает у пустых записей — тогда ratio не считаем
        if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise IntakeError(f"Подозрительная степень сжатия у {info.filename!r} (возможна zip-бомба)")
        # симлинки и прочие необычные типы — отклоняем
        if info.external_attr >> 16 & 0o170000 == 0o120000:
            raise IntakeError(f"Символическая ссылка в архиве: {info.filename!r}")
    files = {}
    for info in entries:
        path = _safe_path(info.filename)
        if path is not None:
            files[path] = archive.read(info)
    return _strip_common_root(files)


def read_upload(uploads: list[tuple[str, bytes]]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for name, data in uploads:
        if name.lower().endswith(".zip"):
            files.update(read_zip(data))
            continue
        if len(data) > MAX_FILE_BYTES:
            raise IntakeError(f"Файл {name!r} больше {MAX_FILE_BYTES // 1024 // 1024} МБ")
        path = _safe_path(PurePosixPath(name.replace("\\", "/")).name)
        if path is not None:
            files[path] = data
    if not any(p.endswith((".py", ".ipynb")) for p in files):
        raise IntakeError("Не найдено ни одного файла .py или .ipynb")
    return files


def read_directory(root: Path) -> dict[str, bytes]:
    """Для CLI и демо-проектов: читает папку с теми же фильтрами, что и архив."""
    files = {}
    for file in sorted(root.rglob("*")):
        if file.is_file():
            path = _safe_path(file.relative_to(root).as_posix())
            if path is not None:
                files[path] = file.read_bytes()
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_UNPACKED_BYTES:
        raise IntakeError("Папка слишком большая")
    return files
