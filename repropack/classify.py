"""Классификация импортов: стандартная библиотека / локальный модуль / внешний пакет PyPI."""

import ast
import codecs
import configparser
import json
import re
import sys
import tomllib
from dataclasses import dataclass, replace
from functools import cache
from importlib import metadata
from pathlib import Path, PurePosixPath

from .scanner import COMPLEXITY_ERRORS, SYNTAX_ERRORS, FileScan

STDLIB = frozenset(sys.stdlib_module_names)
PYTHON2 = (2, 7)
# Модули, которых нет в современных версиях Python: (версия удаления, замена на PyPI)
REMOVED_STDLIB = {
    "distutils": ((3, 12), "setuptools"), "imp": ((3, 12), ""), "asynchat": ((3, 12), ""),
    "asyncore": ((3, 12), ""), "smtpd": ((3, 12), "aiosmtpd"), "cgi": ((3, 13), "legacy-cgi"),
    "cgitb": ((3, 13), ""), "crypt": ((3, 13), ""), "imghdr": ((3, 13), ""), "telnetlib": ((3, 13), ""),
    "pipes": ((3, 13), ""), "nntplib": ((3, 13), ""), "uu": ((3, 13), ""), "xdrlib": ((3, 13), ""),
    "audioop": ((3, 13), ""), "chunk": ((3, 13), ""), "mailcap": ((3, 13), ""), "sndhdr": ((3, 13), ""),
    "sunau": ((3, 13), ""), "spwd": ((3, 13), ""), "nis": ((3, 13), ""), "msilib": ((3, 13), ""),
    "ossaudiodev": ((3, 13), ""), "lib2to3": ((3, 13), ""),
    **{m: (PYTHON2, "") for m in ("urllib2", "ConfigParser", "cPickle", "cStringIO", "StringIO",
                                  "Tkinter", "Queue", "httplib", "urlparse", "HTMLParser", "__builtin__")},
}
# Модули стандартной библиотеки, которых нет в более старых версиях Python
STDLIB_ADDED = {"tomllib": (3, 11), "zoneinfo": (3, 9), "graphlib": (3, 9)}
# Методы pandas, которые молча требуют дополнительный пакет
IMPLICIT = {
    "read_excel": ("openpyxl", "pandas.read_excel"), "to_excel": ("openpyxl", "pandas.to_excel"),
    "read_parquet": ("pyarrow", "pandas.read_parquet"), "to_parquet": ("pyarrow", "pandas.to_parquet"),
    "read_feather": ("pyarrow", "pandas.read_feather"), "read_hdf": ("tables", "pandas.read_hdf"),
    "to_hdf": ("tables", "pandas.to_hdf"),
}
PANDAS_LIKE = {"pandas", "geopandas", "modin", "dask"}  # у polars и других read_excel требует другие пакеты
NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
REQ_LINE = re.compile(rf"^({NAME})\s*(\[[^\]]*\])?\s*([^;]*)")
CONDA_SPEC = re.compile(rf"^(?:[\w.-]+::)?({NAME})\s*(==|>=|<=|!=|~=|=|>|<)?\s*([^\s#]*)")
POETRY_RANGE = re.compile(r"([\^~])\s*(\d+(?:\.\d+)*)")
_OPERATOR = r"(?:==|!=|<=|>=|~=|<|>)"
_VERSION = r"\d[A-Za-z0-9.*+!_-]*"
# Версия для requirements.txt: «1.26.4», «>=2.0», «>=1.2,<2» или пусто. Шаблон совместим с JavaScript:
# интерфейс проверяет им ячейки таблицы
VERSION_SPEC = re.compile(rf"^\s*(?:(?:{_OPERATOR}\s*)?{_VERSION}\s*(?:,\s*{_OPERATOR}\s*{_VERSION}\s*)*)?$")
PACKAGED_CATEGORIES = ("external", "implicit", "declared_only", "removed")
DECLARED_ONLY_NOTE = "объявлено, но import не найден (плагин, бэкенд или лишняя зависимость)"
CONDA_ONLY_NOTE = "пакет conda без import в коде — в requirements.txt не включён"
LOCAL_ENV = "локальная среда"  # имя или версия прочитаны из среды, где запущен repro-packer
NOT_ON_PYPI = "не с PyPI"  # статус модуля, который из PyPI не поставить
MAPPING_FILE = Path(__file__).parent / "data" / "module_to_package.json"


@dataclass(frozen=True)
class Declared:
    name: str
    spec: str
    source: str
    conda: bool = False  # пакет conda не из секции pip: — на PyPI его может не быть
    note: str = ""       # пакет объявлен в нескольких файлах с разными версиями


@dataclass(frozen=True)
class Dependency:
    module: str
    category: str            # stdlib | removed | local | external | implicit | declared_only | conda_only
    package: str = ""
    status: str = ""         # откуда известно имя пакета
    candidates: tuple[str, ...] = ()
    version: str = ""        # спецификатор версии, например "==1.26.4"; "" — неизвестна
    version_source: str = ""
    kinds: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()
    needs_confirmation: bool = False
    note: str = ""


@cache
def load_mapping() -> dict[str, dict]:
    """Разделы справочника: known, ambiguous, alternatives, not_on_pypi, conda_to_pypi."""
    return json.loads(MAPPING_FILE.read_text(encoding="utf-8"))


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _text(data: bytes) -> str:
    """pip freeze в PowerShell пишет UTF-16, Блокнот — UTF-8 с BOM."""
    utf16 = data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    return data.decode("utf-16" if utf16 else "utf-8-sig", "replace")


def _notes(*notes: str) -> str:
    return "; ".join(filter(None, notes))


def _clean_spec(spec: str) -> str:
    """Спецификатор, понятный pip; ссылки, маркеры и прочее — «версия неизвестна»."""
    spec = spec.strip()
    return spec if VERSION_SPEC.match(spec) else ""


def _requirement(line: str) -> tuple[str, str] | None:
    """Имя и версия из строки requirements; опции pip, ссылки и пути к папкам пропускаются.

    «pkg @ https://…» — прямая ссылка: имя пакета известно, версия — нет.
    """
    line = line.split("#", 1)[0].split(" --", 1)[0].strip().rstrip("\\").strip()
    name_part = line.partition("@")[0]
    if not line or line.startswith("-") or "/" in name_part or ":" in name_part:
        return None
    match = REQ_LINE.match(name_part)
    if not match:
        return None
    return match.group(1), "" if "@" in line else _clean_spec(match.group(3))


def _from_lines(lines: list[str], source: str) -> list[Declared]:
    return [Declared(*req, source) for req in map(_requirement, lines) if req]


def _table(data: object, *keys: str) -> dict:
    """Вложенная таблица TOML или {}: файл автора может быть устроен как угодно."""
    for key in keys:
        data = data.get(key) if isinstance(data, dict) else None
    return data if isinstance(data, dict) else {}


def _poetry_spec(spec: object) -> str | None:
    """Версия Poetry → спецификатор pip: ^1.2 → >=1.2,<2; ~1.2.3 → >=1.2.3,<1.3; 2.0 → ==2.0.

    None — зависимость не с PyPI (path, git, url, file).
    """
    if isinstance(spec, dict):
        if spec.keys() & {"path", "git", "url", "file"}:
            return None
        spec = spec.get("version", "")
    spec = str(spec).strip()
    if match := POETRY_RANGE.fullmatch(spec):
        operator, version = match.groups()
        parts = [int(p) for p in version.split(".")]
        bump = (next((i for i, p in enumerate(parts) if p), len(parts) - 1) if operator == "^"
                else min(1, len(parts) - 1))
        return f">={version},<{'.'.join(map(str, [*parts[:bump], parts[bump] + 1]))}"
    if re.fullmatch(r"\d+(\.\d+)*(\.\*)?", spec):
        return f"=={spec}"
    return _clean_spec(spec)


def _from_table(table: dict, source: str) -> list[Declared]:
    """Poetry и Pipfile: {имя: версия или таблица}; python и зависимости не с PyPI пропускаются."""
    found = []
    for name, spec in table.items():
        version = None if name == "python" or not re.fullmatch(NAME, name) else _poetry_spec(spec)
        if version is not None:
            found.append(Declared(name, version, source))
    return found


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, (list, tuple)) else []


def _from_pyproject(text: str, source: str) -> tuple[list[Declared], str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [], ""
    project = _table(data, "project")
    poetry = _table(data, "tool", "poetry", "dependencies")
    found = _from_lines(_strings(project.get("dependencies")), source) + _from_table(poetry, source)
    return found, str(project.get("requires-python") or poetry.get("python") or "")


def _from_pipfile(text: str, source: str) -> tuple[list[Declared], str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [], ""
    return _from_table(_table(data, "packages"), source), str(_table(data, "requires").get("python_version") or "")


def _from_setup_cfg(text: str, source: str) -> tuple[list[Declared], str]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return [], ""
    lines = parser.get("options", "install_requires", fallback="").splitlines()
    return _from_lines(lines, source), parser.get("options", "python_requires", fallback="")


def _literal(node: ast.expr) -> object:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _setup_arguments(tree: ast.AST) -> dict[str, ast.expr]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "setup":
            return {k.arg: k.value for k in node.keywords if k.arg}
    return {}


def _from_setup_py(text: str, source: str) -> tuple[list[Declared], str]:
    """setup.py не выполняется: из вызова setup(...) берутся только списки и строки, записанные буквально."""
    try:
        arguments = _setup_arguments(ast.parse(text))
    except (*SYNTAX_ERRORS, *COMPLEXITY_ERRORS):
        return [], ""
    missing = ast.Constant(None)
    requires, python = (_literal(arguments.get(key, missing)) for key in ("install_requires", "python_requires"))
    return _from_lines(_strings(requires), source), python if isinstance(python, str) else ""


def _conda_entries(text: str) -> list[tuple[str, bool]]:
    """Элементы списка dependencies: из environment.yml и флаг «из секции pip:»."""
    entries, section, pip_indent = [], "", -1
    for line in text.splitlines():
        item, indent = line.strip(), len(line) - len(line.lstrip())
        if indent == 0 and item and not item.startswith(("-", "#")):
            section, pip_indent = item.split(":", 1)[0].strip(), -1
        elif section == "dependencies" and item.startswith("-"):
            entry, in_pip = item[1:].split(" #", 1)[0].strip().strip("\"'"), 0 <= pip_indent < indent
            if not in_pip:
                pip_indent = indent if entry.replace(" ", "") == "pip:" else -1
            entries.append((entry, in_pip))
    return entries


def _conda_spec(operator: str, version: str, build: str) -> str:
    """«=1.24» в conda — любая 1.24.x; со строкой сборки (conda env export) версия точная."""
    if operator == "=":
        operator, version = "==", version if build or version.endswith("*") else f"{version}.*"
    return _clean_spec(f"{operator}{version}") if version else ""


def _from_conda(text: str, source: str) -> tuple[list[Declared], str]:
    """environment.yml, в том числе от conda env export: «numpy=1.26.4=py311h64a7726_0»."""
    found, python = [], ""
    for entry, in_pip in _conda_entries(text):
        if in_pip:
            if req := _requirement(entry):
                found.append(Declared(*req, source))
            continue
        match = CONDA_SPEC.match(entry)
        if not match or match.group(1) == "pip":
            continue
        name, operator, raw = match.group(1), match.group(2) or "", match.group(3)
        name = load_mapping()["conda_to_pypi"].get(name, name)  # pytorch → torch, py-opencv → opencv-python
        version, _, build = raw.partition("=") if operator in ("=", "==") else (raw, "", "")
        if name == "python":
            python = version if operator in ("", "=", "==") else f"{operator}{version}"
        else:
            found.append(Declared(name, _conda_spec(operator, version, build), source, conda=True))
    return found, python


# Файл зависимостей → (разбор, версия Python в нём точная: среда автора важнее диапазона requires-python)
READERS = {
    "pyproject.toml": (_from_pyproject, False), "setup.cfg": (_from_setup_cfg, False),
    "setup.py": (_from_setup_py, False), "Pipfile": (_from_pipfile, True),
    "environment.yml": (_from_conda, True), "environment.yaml": (_from_conda, True),
}


def _declared_items(files: dict[str, bytes]) -> tuple[list[Declared], str]:
    items: list[Declared] = []
    python = ""
    for path, data in sorted(files.items()):  # порядок файлов в ZIP не должен влиять на результат
        name = PurePosixPath(path).name
        if name.startswith("requirements") and name.endswith(".txt"):
            items += _from_lines(_text(data).splitlines(), path)
        elif name in READERS:
            read, exact = READERS[name]
            found, hint = read(_text(data), path)
            items, python = items + found, (hint or python) if exact else (python or hint)
    return items, python


def _pinned(spec: str) -> bool:
    return spec.startswith("==") and "*" not in spec


def _merge(group: list[Declared]) -> Declared:
    """Пакет объявлен в нескольких местах: точная версия важнее диапазона, pip — важнее conda."""
    best = min(group, key=lambda d: (not d.spec, not _pinned(d.spec), d.conda))
    with_spec = [d for d in group if d.spec]
    conflict = len({d.spec for d in with_spec}) > 1
    note = "версии в файлах расходятся: " + ", ".join(f"{d.spec} ({d.source})" for d in with_spec) if conflict else ""
    return replace(best, conda=all(d.conda for d in group), note=note)


def _merge_declared(items: list[Declared]) -> dict[str, Declared]:
    groups: dict[str, list[Declared]] = {}
    for item in items:
        groups.setdefault(normalize(item.name), []).append(item)
    return {key: _merge(group) for key, group in groups.items()}


def parse_declared(files: dict[str, bytes]) -> tuple[dict[str, Declared], str]:
    """Зависимости, уже объявленные в проекте: requirements*.txt, pyproject.toml, setup.cfg, setup.py,
    Pipfile, environment.yml. Файлы только читаются, setup.py разбирается через ast."""
    items, python = _declared_items(files)
    return _merge_declared(items), python


def _module_exists(prefix: str, top: str, files: dict[str, bytes]) -> bool:
    return f"{prefix}{top}.py" in files or any(p.startswith(f"{prefix}{top}/") for p in files)


def is_local(top: str, importer: str, files: dict[str, bytes]) -> bool:
    """Модуль локальный, если рядом с импортирующим файлом, в корне или в src/ есть top.py или папка top/."""
    folders = {str(PurePosixPath(importer).parent), ".", "src"}
    return any(_module_exists("" if f == "." else f"{f}/", top, files) for f in folders)


@cache
def _installed_modules() -> dict[str, list[str]]:
    """Модуль верхнего уровня → дистрибутивы в текущей среде (дорого считать, поэтому один раз)."""
    return metadata.packages_distributions()


def _local_env_distribution(top: str) -> str:
    return next(iter(_installed_modules().get(top, [])), "")


def _local_env_version(package: str) -> str:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return ""


def _declared_choice(candidates: tuple[str, ...], declared: dict[str, Declared]) -> str:
    return next((c for c in candidates if normalize(c) in declared), "")


def _resolve_package(module: str, declared: dict[str, Declared], use_local_env: bool) -> dict:
    mapping = load_mapping()
    if module in mapping["not_on_pypi"]:
        return {"status": NOT_ON_PYPI, "needs_confirmation": True, "note": mapping["not_on_pypi"][module]}
    if variant := _declared_choice(tuple(mapping["alternatives"].get(module, ())), declared):
        return {"package": variant, "status": "объявлено в проекте"}  # opencv-python-headless вместо opencv-python
    if module in mapping["known"]:
        return {"package": mapping["known"][module], "status": "справочник"}
    if module in mapping["ambiguous"]:
        candidates = tuple(mapping["ambiguous"][module])
        if chosen := _declared_choice(candidates, declared):
            return {"package": chosen, "status": "объявлено в проекте", "candidates": candidates}
        return {"package": candidates[0], "status": "неоднозначно", "candidates": candidates,
                "needs_confirmation": True, "note": "несколько пакетов дают этот модуль — выберите нужный"}
    if normalize(module) in declared:
        return {"package": declared[normalize(module)].name, "status": "объявлено в проекте"}
    if use_local_env and (dist := _local_env_distribution(module)):
        return {"package": dist, "status": LOCAL_ENV}
    return {"package": module, "status": "догадка", "needs_confirmation": True,
            "note": "нет в справочнике: это пакет PyPI с другим именем или забытый локальный модуль?"}


def _version(package: str, declared: dict[str, Declared], use_local_env: bool,
             module: str = "") -> tuple[str, str, str]:
    """Версия, откуда она и пометка о расхождении версий между файлами."""
    for name in filter(None, (package, module)):
        if (found := declared.get(normalize(name))) and found.spec:
            return found.spec, found.source, found.note
    if use_local_env and package and (version := _local_env_version(package)):
        return f"=={version}", LOCAL_ENV, ""
    return "", "", ""


def _removed(top: str, common: dict) -> Dependency:
    removed_in, replacement = REMOVED_STDLIB[top]
    note = ("модуль Python 2 — в Python 3 его нет" if removed_in == PYTHON2
            else f"удалён из стандартной библиотеки в Python {removed_in[0]}.{removed_in[1]}")
    return Dependency(category="removed", package=replacement, status="стандартная библиотека",
                      needs_confirmation=bool(replacement), note=note, **common)


def _module_key(module: str, declared: dict[str, Declared]) -> str:
    """Имя для поиска пакета: самое длинное известное («google.cloud.storage», «ruamel.yaml» из requirements),
    иначе модуль верхнего уровня («numpy.linalg» → «numpy»)."""
    mapping, parts = load_mapping(), module.split(".")
    listed = (".".join(parts[:n]) for n in range(len(parts), 1, -1))
    return next((name for name in listed if normalize(name) in declared
                 or any(name in mapping[s] for s in ("known", "ambiguous", "not_on_pypi"))), parts[0])


def _collect_usages(scans: list[FileScan], declared: dict[str, Declared]) -> dict[str, list[tuple[str, str, str]]]:
    """Модуль → [(файл, место для отчёта, вид импорта)]."""
    usages: dict[str, list[tuple[str, str, str]]] = {}
    for scan in scans:
        for ref in scan.imports:
            if ref.kind != "relative" and ref.top:
                key = _module_key(ref.module, declared)
                usages.setdefault(key, []).append((scan.path, scan.where(ref.line), ref.kind))
    return usages


def _classify_module(module: str, uses: list[tuple[str, str, str]], files: dict[str, bytes],
                     declared: dict[str, Declared], use_local_env: bool) -> Dependency:
    top = module.split(".", 1)[0]
    common = {"module": module, "kinds": tuple(sorted({kind for _, _, kind in uses})),
              "locations": tuple(where for _, where, _ in uses)}
    if top in REMOVED_STDLIB:
        return _removed(top, common)
    if top in STDLIB and _module_exists("", top, files):
        return Dependency(category="local", **common,
                          note="имя совпадает с модулем стандартной библиотеки — Python возьмёт файл проекта")
    if top in STDLIB:
        return Dependency(category="stdlib", **common)
    if any(is_local(top, path, files) for path, _, _ in uses):
        return Dependency(category="local", **common)
    resolved = _resolve_package(module, declared, use_local_env)
    version, source, conflict = _version(resolved.get("package", ""), declared, use_local_env, module)
    return Dependency(category="external", version=version, version_source=source,
                      **{**resolved, "note": _notes(resolved.get("note", ""), conflict)}, **common)


def _packages(deps: list[Dependency]) -> set[str]:
    return ({normalize(d.package) for d in deps if d.package}
            | {normalize(d.module) for d in deps if d.category == "external"})


def _implicit(scans: list[FileScan], usages: dict, deps: list[Dependency], declared: dict[str, Declared],
              use_local_env: bool) -> list[Dependency]:
    if not usages.keys() & PANDAS_LIKE:
        return []
    found, seen = [], _packages(deps)
    for scan in scans:
        for method in sorted(scan.method_calls & IMPLICIT.keys()):
            package, origin = IMPLICIT[method]
            if normalize(package) in seen:
                continue
            seen.add(normalize(package))
            version, source, conflict = _version(package, declared, use_local_env)
            found.append(Dependency(module=package, category="implicit", package=package, status="неявная",
                                    version=version, version_source=source, locations=(scan.path,),
                                    needs_confirmation=True,
                                    note=_notes(f"{origin} требует этот пакет, хотя import нет", conflict)))
    return found


def _declared_only(declared: dict[str, Declared], packages: set[str]) -> list[Dependency]:
    """Объявлено автором, но не импортируется. Пакеты conda в requirements не идут: многие из них —
    системные библиотеки (openssl, libgcc), которых нет на PyPI."""
    return [Dependency(module=item.name, category="conda_only" if item.conda else "declared_only",
                       package=item.name, status="объявлено в проекте", version=item.spec,
                       version_source=item.source, locations=(item.source,),
                       note=_notes(CONDA_ONLY_NOTE if item.conda else DECLARED_ONLY_NOTE, item.note))
            for key, item in declared.items() if key not in packages]


def classify(scans: list[FileScan], files: dict[str, bytes], use_local_env: bool = False) -> list[Dependency]:
    items, _ = _declared_items(files)
    hints = [Declared(*req, f"{scan.path} (!pip install)")
             for scan in scans for req in map(_requirement, scan.pip_hints) if req]
    declared = _merge_declared(items + hints)  # при равной точности версия из файлов автора важнее !pip install
    usages = _collect_usages(scans, declared)
    deps = [_classify_module(module, usages[module], files, declared, use_local_env)
            for module in sorted(usages, key=str.lower)]
    deps += _implicit(scans, usages, deps, declared, use_local_env)
    return deps + _declared_only(declared, _packages(deps))
