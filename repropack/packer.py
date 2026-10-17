"""Сборка пакета: requirements.txt, README, Dockerfile, отчёт, verify-скрипты → ZIP."""

import hashlib
import io
import json
import posixpath
import re
import shlex
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import __version__
from .analysis import Analysis
from .classify import LOCAL_ENV, PACKAGED_CATEGORIES, VERSION_SPEC, Dependency, normalize
from .markdown import code, escape
from .secrets import env_names, find_secrets, read_text, redact, redact_bytes, scan

TEMPLATES = Environment(loader=FileSystemLoader(Path(__file__).parent / "data" / "templates"),
                        keep_trailing_newline=True, undefined=StrictUndefined, autoescape=False)
# Пользовательские строки в Markdown: имя проекта и файлы — экранируются, код в обратных кавычках — оборачивается
TEMPLATES.filters["md"] = escape
TEMPLATES.filters["mdcode"] = code
# Ячейка таблицы: «|» делит ячейки даже внутри кода в обратных кавычках, поэтому экранируется и там
TEMPLATES.filters["mdcell"] = lambda text: code(text).replace("|", "\\|")
CATEGORIES = {"stdlib": "стандартная библиотека", "removed": "удалён из Python", "local": "локальный модуль",
              "external": "внешний пакет", "implicit": "неявная зависимость", "declared_only": "объявлен автором",
              "conda_only": "пакет conda (не для pip)"}
LEVELS = {"high": "критично", "medium": "нужно решение", "info": "к сведению"}
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?$")
# ASCII-цифры целиком: «$» пропускает завершающий перевод строки, а \d — цифры вроде «３.１１»
PYTHON_VERSION = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}")  # длина ограничена: из неё строится список версий для verify
VERSION_OPERATORS = ("==", ">=", "<=", "~=", "!=", ">", "<")
NOTEBOOK_RUNNERS = ("nbconvert", "ipykernel")
# Системные библиотеки Debian, без которых пакет не ставится или не импортируется в образе python:*-slim
SYSTEM_PACKAGES = {
    "opencv-python": "libgl1 libglib2.0-0", "opencv-contrib-python": "libgl1 libglib2.0-0",
    "psycopg2": "libpq-dev gcc", "mysqlclient": "default-libmysqlclient-dev pkg-config gcc",
    "pyaudio": "portaudio19-dev gcc", "pygraphviz": "graphviz graphviz-dev gcc",
}
# Docker отправляет демону всю папку: окружение и логи verify.sh не нужны и весят сотни мегабайт
# Docker копирует всю папку: окружение, логи и файлы с секретами в образ не нужны. Порядок важен: последнее правило побеждает
DOCKERIGNORE = "\n".join([
    ".repro-venv/", "verify_log.txt", "run_output.txt",
    "**/.env*", "!**/.env.example", "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.keystore",
    "**/*.jks", "**/*.p8", "**/*.ppk", "**/*.tfvars", "**/.netrc", "**/.pypirc", "**/.npmrc",
    "**/.aws/", "**/.ssh/", "**/.docker/", "**/.kube/", "**/credentials.json", "**/secrets.toml", ""])
TEMPLATED = ("README.md", "REPORT.md", "Dockerfile", "verify.sh", "verify.ps1")
# Корень пакета для дерева в README: файл → зачем он коллеге
PACKAGE_FILES = {
    "README.md": "как установить и запустить", "requirements.txt": "зависимости с пояснением к каждой строке",
    "REPORT.md": "что определить не удалось", "repro.json": "отчёт в машиночитаемом виде",
    "Dockerfile": "запуск в контейнере", ".dockerignore": "что не копировать в образ",
    "verify.sh": "проверка в чистом окружении: Linux, macOS", "verify.ps1": "проверка в чистом окружении: Windows",
}
TREE_NOTE_COLUMN = 40  # символов: пояснения в дереве выровнены в одну колонку
TREE_LIMIT = 40  # строк: у большого проекта дерево обрезается, полный состав — в самом архиве
SLUG_LIMIT = 40  # символов: тег Docker-образа — до 128, имя папки — до 255 байт
SLUG_HASH = 8  # шестнадцатеричных знаков sha256 исходного имени
NEWEST_PYTHON_MINOR = 14  # verify-скрипты ищут нужный Python, а если его нет — ближайший новее, до 3.14
ENV_TEMPLATE_HEADER = ("# Создано repro-packer вместо исключённого файла с секретами: значения автора удалены.\n"
                       "# Впишите свои значения и переименуйте файл в .env\n")


@dataclass(frozen=True)
class Requirement:
    package: str
    version: str = ""
    comment: str = ""
    confirmed: bool = True


@dataclass(frozen=True)
class PackOptions:
    project_name: str
    entry_point: str
    python_version: str
    requirements: tuple[Requirement, ...]
    run_args: str = ""


def packaged_dependencies(analysis: Analysis) -> tuple[Dependency, ...]:
    """Зависимости, которые попадут в requirements; одинаковые пакеты от разных модулей схлопываются."""
    seen, deps = set(), []
    for d in analysis.dependencies:
        if d.category in PACKAGED_CATEGORIES and d.package and normalize(d.package) not in seen:
            seen.add(normalize(d.package))
            deps.append(d)
    return tuple(deps)


def _comment(d: Dependency) -> str:
    if d.category != "external":
        return d.note
    return "необязательная (импорт в try/except)" if d.kinds == ("optional",) else ""


def default_requirements(analysis: Analysis) -> tuple[Requirement, ...]:
    return tuple(Requirement(d.package, d.version, _comment(d), not d.needs_confirmation)
                 for d in packaged_dependencies(analysis))


def _spec(version: str) -> str:
    version = version.strip()
    if not version:
        return ""
    return version if version.startswith(VERSION_OPERATORS) else f"=={version}"


def _validate(req: Requirement) -> None:
    # fullmatch: «$» в шаблоне (он же уходит в проверку таблицы на JS) пропускает завершающий перевод строки
    if not PACKAGE_NAME.fullmatch(req.package):
        raise ValueError(f"Некорректное имя пакета: {req.package!r}")
    if not VERSION_SPEC.fullmatch(req.version):
        raise ValueError(f"Некорректная версия для {req.package}: {req.version!r}")


def _with_notebook_runners(options: PackOptions) -> tuple[Requirement, ...]:
    reqs = options.requirements
    if not options.entry_point.endswith(".ipynb"):
        return reqs
    present = {normalize(r.package) for r in reqs}
    extra = [Requirement(p, comment="нужен для запуска ноутбука") for p in NOTEBOOK_RUNNERS if p not in present]
    return (*reqs, *extra)


def requirements_text(reqs: tuple[Requirement, ...], created: str) -> str:
    lines = [f"# Черновик зависимостей, создан repro-packer {created}.",
             "# Проверьте его командой: sh verify.sh — точные версии появятся в requirements.lock.txt", ""]
    for req in reqs:
        _validate(req)
        spec = _spec(req.version)
        notes = [] if spec else ["версия неизвестна"]
        if not req.confirmed:
            notes.append("НЕ ПОДТВЕРЖДЕНО — проверьте имя пакета")
        # «\» в конце строки pip считает переносом: следующая строка с пакетом приклеилась бы к комментарию
        if comment := " ".join(req.comment.split()).rstrip("\\ "):
            notes.append(comment)
        line = f"{req.package}{spec}"
        row = f"{line:<32} # {'; '.join(notes)}" if notes else line
        lines.append(row if req.confirmed else f"# {row}")  # имя без проверки не ставим: строка закомментирована
    return "\n".join(lines) + "\n"


def run_parts(entry_point: str, run_args: str) -> list[str]:
    # Имя файла с «-» в начале python принял бы за ключ: «-copen(…)#.py» выполнил бы код из имени, а не скрипт
    entry = f"./{entry_point}" if entry_point.startswith("-") else entry_point
    if entry.endswith(".ipynb"):
        return ["-m", "nbconvert", "--to", "notebook", "--execute", entry, "--output", "executed.ipynb"]
    try:
        return [entry, *shlex.split(run_args)]
    except ValueError as exc:
        raise ValueError(f"Аргументы запуска не разобрать (незакрытая кавычка?): {run_args!r}") from exc


def ps_quote(text: str) -> str:
    """Литерал PowerShell в одинарных кавычках: $(...) не раскрывается; ' и типографские ‘’‚‛ удваиваются."""
    return "'" + re.sub("['‘’‚‛]", lambda m: m.group() * 2, text) + "'"


def slugify(name: str) -> str:
    """Имя папки в архиве и Docker-образа: латиница, цифры и «-». Если буквы потерялись (кириллица, пустое имя)
    или имя обрезано — добавляется хэш исходного имени: иначе «опыт 1» и «опыт 2» дали бы один образ «project»."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if slug and name.isascii() and len(slug) <= SLUG_LIMIT:
        return slug
    digest = hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()[:SLUG_HASH]
    return f"{slug[:SLUG_LIMIT].strip('-') or 'project'}-{digest}"


def _tree_lines(node: dict, parent: str, notes: dict[str, str]) -> list[tuple[str, str]]:
    """Строки дерева с пояснениями: сначала файлы, потом папки, по алфавиту."""
    lines = []
    items = sorted(node.items(), key=lambda item: (bool(item[1]), item[0].lower()))
    for number, (name, children) in enumerate(items, start=1):
        path, last = posixpath.join(parent, name), number == len(items)
        lines.append((f"{'└── ' if last else '├── '}{name}{'/' if children else ''}", notes.get(path, "")))
        lines += [(("    " if last else "│   ") + text, note) for text, note in _tree_lines(children, path, notes)]
    return lines


def package_tree(root: str, paths: list[str], notes: dict[str, str]) -> str:
    """Структура папок пакета для README: коллега сразу видит, что где лежит."""
    tree: dict = {}
    for path in paths:
        node = tree
        for part in path.split("/"):
            node = node.setdefault(part, {})
    lines = [f"{text:<{TREE_NOTE_COLUMN}} ← {note}" if note else text for text, note in _tree_lines(tree, "", notes)]
    if len(lines) > TREE_LIMIT:
        lines = [*lines[:TREE_LIMIT], f"… и ещё {len(lines) - TREE_LIMIT} — полный состав в архиве"]
    return "\n".join([f"{root}/", *lines])


def _package_tree(analysis: Analysis, options: PackOptions) -> str:
    sources = [p for p in analysis.files if p not in analysis.secret_files] + list(env_templates(analysis))
    notes = {**PACKAGE_FILES, "project": "код и данные автора", f"project/{options.entry_point}": "точка входа",
             **{f"project/{p}": "входные данные" for p in analysis.data_found},
             **{f"project/{p}": "имена переменных без значений — впишите свои" for p in env_templates(analysis)}}
    return package_tree(f"{slugify(options.project_name)}-repro",
                        [*PACKAGE_FILES, *(f"project/{p}" for p in sources)], notes)


def python_candidates(version: str) -> list[str]:
    """Версии, которые verify-скрипт пробует по порядку: нужная, затем новее (минимальная подходящая — первой)."""
    major, minor = map(int, version.split("."))
    return [version, *(f"{major}.{m}" for m in range(minor + 1, NEWEST_PYTHON_MINOR + 1) if major == 3)]


def _context(analysis: Analysis, options: PackOptions, reqs: tuple[Requirement, ...], created: str) -> dict:
    parts = run_parts(options.entry_point, options.run_args)
    system = [(r.package, SYSTEM_PACKAGES[normalize(r.package)]) for r in reqs
              if normalize(r.package) in SYSTEM_PACKAGES]
    run_tail = shlex.join(parts)
    # В README, журнале и repro.json аргументы показываем без секретов; сама команда (run_tail) — настоящая
    run_log = redact(f"-- Запуск: python {run_tail}")
    return {
        "project_name": options.project_name, "slug": slugify(options.project_name), "created": created,
        "tree": _package_tree(analysis, options),
        "python_version": options.python_version, "python_reason": analysis.python_reason,
        "python_candidates": python_candidates(options.python_version),
        "requirements": reqs, "unknown_versions": [r.package for r in reqs if not _spec(r.version)],
        "system_packages": system, "system_apt": " ".join(dict.fromkeys(" ".join(a for _, a in system).split())),
        "run_tail": run_tail, "run_command": redact(f"python {run_tail}"), "cmd_json": json.dumps(["python", *parts]),
        "run_command_ps": redact(" ".join(["python", *map(ps_quote, parts)])),
        "run_tail_ps": " ".join(map(ps_quote, parts)),
        "run_log_sh": shlex.quote(run_log), "run_log_ps": ps_quote(run_log),
        "data_found": analysis.data_found, "data_missing": analysis.data_missing,
        "excluded": analysis.secret_files, "redacted": bool(analysis.secrets), "env_templates": env_templates(analysis),
        "key_issues": [i for i in analysis.issues if i.level != "info"], "issues": analysis.issues,
        "dependencies": analysis.dependencies, "hygiene": analysis.hygiene, "environment": analysis.environment,
        "local_versions": [d for d in analysis.dependencies if d.version_source == LOCAL_ENV],
        "not_installed": [d.package for d in packaged_dependencies(analysis) if not d.version],
        "categories": CATEGORIES, "levels": LEVELS,
        "counts": {lvl: sum(i.level == lvl for i in analysis.issues) for lvl in LEVELS},
    }


def _manifest(analysis: Analysis, options: PackOptions, reqs: tuple[Requirement, ...], ctx: dict) -> str:
    return json.dumps({
        "tool": f"repro-packer {__version__}", "created": ctx["created"],
        "entry_point": options.entry_point, "python": options.python_version, "run_command": ctx["run_command"],
        "requirements": [asdict(r) for r in reqs],
        "dependencies": [asdict(d) for d in analysis.dependencies],
        "issues": [asdict(i) for i in analysis.issues],
        "excluded_files": list(analysis.secret_files),
        "redacted_files": sorted({h.path for h in analysis.secrets}),
        "local_environment": dict(analysis.environment),
    }, ensure_ascii=False, indent=2)


def render_package(analysis: Analysis, options: PackOptions, created: str | None = None) -> dict[str, str]:
    """Сгенерированные файлы пакета (без исходников) — для предпросмотра в интерфейсе и для ZIP."""
    if not PYTHON_VERSION.fullmatch(options.python_version):
        raise ValueError(f"Некорректная версия Python: {options.python_version!r} — нужна вида 3.11")
    created = created or datetime.now(timezone.utc).isoformat(timespec="seconds")
    reqs = _with_notebook_runners(options)
    ctx = _context(analysis, options, reqs, created)
    rendered = {name: TEMPLATES.get_template(f"{name}.j2").render(ctx)
                for name in TEMPLATED}
    return {**rendered, "requirements.txt": requirements_text(reqs, created), ".dockerignore": DOCKERIGNORE,
            "repro.json": _manifest(analysis, options, reqs, ctx)}


def env_templates(analysis: Analysis) -> dict[str, str]:
    """Вместо исключённого .env — .env.example с именами переменных без значений; шаблон автора не трогаем."""
    names: dict[str, list[str]] = {}
    for path in analysis.secret_files:
        target = posixpath.join(posixpath.dirname(path), ".env.example")
        names.setdefault(target, []).extend(env_names(path, read_text(analysis.files[path], path)))
    return {target: ENV_TEMPLATE_HEADER + "".join(f"{name}=\n" for name in dict.fromkeys(found))
            for target, found in names.items() if found and target not in analysis.files}


def _project_files(analysis: Analysis) -> dict[str, bytes]:
    """Исходники для пакета: без файлов-секретов; каждый текстовый файл вымаран, а не только те, где анализ нашёл."""
    sources = {path: redact_bytes(path, data)
               for path, data in analysis.files.items() if path not in analysis.secret_files}
    # Страховка: значение, оставшееся после вымарывания в любом файле (в двоичном его не вымарать), не уходит в пакет
    if leaked := [path for path, data in sources.items() if scan(path, data)]:
        raise ValueError(f"секрет в {', '.join(sorted(redact(p, plain=True) for p in leaked))} не удалось заменить "
                         "на <REDACTED> — уберите его из файла вручную")
    return {**sources, **{path: text.encode() for path, text in env_templates(analysis).items()}}


def build_zip(analysis: Analysis, options: PackOptions) -> bytes:
    if options.entry_point not in analysis.files:
        raise ValueError(f"Точка входа {options.entry_point!r} не найдена в проекте")
    root = f"{slugify(options.project_name)}-repro"
    generated = {name: text.encode("utf-8-sig" if name.endswith(".ps1") else "utf-8")
                 for name, text in render_package(analysis, options).items()}
    entries = {**{f"project/{p}": data for p, data in _project_files(analysis).items()}, **generated}
    # Последний рубеж: ключ из аргументов запуска, таблицы зависимостей или имени файла не попадает в пакет
    if leaked := sorted(redact(name, plain=True) for name, data in entries.items()
                        if find_secrets(name, name) or name in generated and find_secrets(name, read_text(data))):
        raise ValueError(f"похоже на секрет (ключ, токен или пароль) в {', '.join(leaked)} — уберите его из "
                         "аргументов запуска, таблицы зависимостей или имени файла и передайте коллеге отдельно")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(f"{root}/{name}", date_time=datetime.now().timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if name == "verify.sh" else 0o644) << 16
            archive.writestr(info, data)
    return buffer.getvalue()
