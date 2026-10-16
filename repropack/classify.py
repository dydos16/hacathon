"""Классификация импортов: стандартная библиотека / локальный модуль / внешний пакет PyPI."""

import json
import re
import sys
import tomllib
from dataclasses import dataclass
from functools import cache
from importlib import metadata
from pathlib import Path, PurePosixPath

from .scanner import FileScan

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
# Методы, которые молча требуют дополнительный пакет
IMPLICIT = {
    "read_excel": ("openpyxl", "pandas.read_excel"), "to_excel": ("openpyxl", "pandas.to_excel"),
    "read_parquet": ("pyarrow", "pandas.read_parquet"), "to_parquet": ("pyarrow", "pandas.to_parquet"),
    "read_feather": ("pyarrow", "pandas.read_feather"), "read_hdf": ("tables", "pandas.read_hdf"),
    "to_hdf": ("tables", "pandas.to_hdf"),
}
REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*)")
CONDA_LINE = re.compile(r"^\s*-\s*(?:[\w-]+::)?([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==|>=|<=|=|>|<|~=)?\s*([^\s#]*)")
MAPPING_FILE = Path(__file__).parent / "data" / "module_to_package.json"


@dataclass(frozen=True)
class Declared:
    name: str
    spec: str
    source: str


@dataclass(frozen=True)
class Dependency:
    module: str
    category: str            # stdlib | removed | local | external | implicit | declared_only
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
def load_mapping() -> tuple[dict[str, str], dict[str, list[str]]]:
    data = json.loads(MAPPING_FILE.read_text(encoding="utf-8"))
    return data["known"], data["ambiguous"]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirement(line: str) -> tuple[str, str] | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    match = REQ_LINE.match(line)
    return (match.group(1), match.group(3).strip()) if match else None


def _from_pyproject(text: str, source: str) -> tuple[list[Declared], str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [], ""
    project = data.get("project", {})
    found = [Declared(*req, source) for req in map(_requirement, project.get("dependencies", [])) if req]
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        if name != "python":
            found.append(Declared(name, spec if isinstance(spec, str) and spec != "*" else "", source))
    return found, project.get("requires-python", "") or str(poetry.get("python", ""))


def _from_conda(text: str, source: str) -> tuple[list[Declared], str]:
    found, python = [], ""
    for line in text.splitlines():
        match = CONDA_LINE.match(line)
        if not match or line.rstrip().endswith(":"):
            continue
        name, op, version = match.groups()
        spec = f"=={version}.*" if op == "=" else f"{op}{version}" if op else ""
        if name == "python":
            python = version
        elif name != "pip":
            found.append(Declared(name, spec, source))
    return found, python


def parse_declared(files: dict[str, bytes]) -> tuple[dict[str, Declared], str]:
    """Зависимости, уже объявленные в проекте (requirements*.txt, pyproject.toml, environment.yml)."""
    declared: list[Declared] = []
    python = ""
    for path, data in files.items():
        name, text = PurePosixPath(path).name, data.decode("utf-8", "replace")
        if name.startswith("requirements") and name.endswith(".txt"):
            declared += [Declared(*req, path) for req in map(_requirement, text.splitlines()) if req]
        elif name == "pyproject.toml":
            found, hint = _from_pyproject(text, path)
            declared, python = declared + found, python or hint
        elif name in ("environment.yml", "environment.yaml"):
            found, hint = _from_conda(text, path)
            declared, python = declared + found, hint or python  # точная версия conda важнее диапазона
    return {normalize(d.name): d for d in declared}, python


def _module_exists(prefix: str, top: str, files: dict[str, bytes]) -> bool:
    return f"{prefix}{top}.py" in files or any(p.startswith(f"{prefix}{top}/") for p in files)


def is_local(top: str, importer: str, files: dict[str, bytes]) -> bool:
    """Модуль локальный, если рядом с импортирующим файлом, в корне или в src/ есть top.py или папка top/."""
    folders = {str(PurePosixPath(importer).parent), ".", "src"}
    return any(_module_exists("" if f == "." else f"{f}/", top, files) for f in folders)


def _local_env_distribution(top: str) -> str:
    dists = metadata.packages_distributions().get(top, [])
    return dists[0] if dists else ""


def _local_env_version(package: str) -> str:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return ""


def _resolve_package(top: str, declared: dict[str, Declared], use_local_env: bool) -> dict:
    known, ambiguous = load_mapping()
    # 1) Явное объявление в проекте побеждает справочник — автор знает, что ему нужно.
    if normalize(top) in declared:
        return {"package": declared[normalize(top)].name, "status": "объявлено в проекте"}
    if top in known:
        # Справочник — не истина: у cv2/PIL/torch бывают варианты. Если один из них
        # объявлен как alternative — предпочитаем его.
        alternatives = known.get(f"{top}#alternatives") or []
        declared_match = next((a for a in alternatives if normalize(a) in declared), "")
        if declared_match:
            return {"package": declared_match, "status": "объявлено в проекте"}
        if alternatives:
            return {"package": known[top], "status": "справочник", "candidates": tuple(alternatives),
                    "needs_confirmation": True,
                    "note": "у этого модуля несколько пакетов — проверьте, какой именно нужен"}
        return {"package": known[top], "status": "справочник"}
    if top in ambiguous:
        candidates = tuple(ambiguous[top])
        chosen = next((c for c in candidates if normalize(c) in declared), "")
        if chosen:
            return {"package": chosen, "status": "объявлено в проекте", "candidates": candidates}
        return {"package": candidates[0], "status": "неоднозначно", "candidates": candidates,
                "needs_confirmation": True, "note": "несколько пакетов дают этот модуль — выберите нужный"}
    if normalize(top) in declared:
        return {"package": declared[normalize(top)].name, "status": "объявлено в проекте"}
    if use_local_env and (dist := _local_env_distribution(top)):
        return {"package": dist, "status": "локальная среда"}
    return {"package": top, "status": "догадка", "needs_confirmation": True,
            "note": "нет в справочнике: это пакет PyPI с другим именем или забытый локальный модуль?"}


def _version(package: str, declared: dict[str, Declared], use_local_env: bool, module: str = "") -> tuple[str, str]:
    for name in filter(None, (package, module)):
        if (found := declared.get(normalize(name))) and found.spec:
            return found.spec, found.source
    if use_local_env and (version := _local_env_version(package)):
        return f"=={version}", "локальная среда"
    return "", ""


def _removed(top: str, common: dict) -> Dependency:
    removed_in, replacement = REMOVED_STDLIB[top]
    note = ("модуль Python 2 — в Python 3 его нет" if removed_in == PYTHON2
            else f"удалён из стандартной библиотеки в Python {removed_in[0]}.{removed_in[1]}")
    return Dependency(category="removed", package=replacement, status="стандартная библиотека",
                      needs_confirmation=bool(replacement), note=note, **common)


def _collect_usages(scans: list[FileScan]) -> dict[str, list[tuple[str, int, str]]]:
    usages: dict[str, list[tuple[str, int, str]]] = {}
    for scan in scans:
        for ref in scan.imports:
            if ref.kind != "relative" and ref.top:
                usages.setdefault(ref.top, []).append((scan.path, ref.line, ref.kind))
    return usages


def _implicit(scans: list[FileScan], known_packages: set[str], declared: dict[str, Declared],
              use_local_env: bool) -> list[Dependency]:
    deps = []
    for scan in scans:
        for method in sorted(scan.method_calls & IMPLICIT.keys()):
            package, origin = IMPLICIT[method]
            if normalize(package) in known_packages:
                continue
            known_packages.add(normalize(package))
            version, source = _version(package, declared, use_local_env)
            deps.append(Dependency(module=package, category="implicit", package=package, status="неявная",
                                   version=version, version_source=source, locations=(scan.path,),
                                   needs_confirmation=True, note=f"{origin} требует этот пакет, хотя import нет"))
    return deps


def classify(scans: list[FileScan], files: dict[str, bytes], use_local_env: bool = False) -> list[Dependency]:
    declared, _ = parse_declared(files)
    for scan in scans:
        for hint in scan.pip_hints:
            if req := _requirement(hint):
                declared.setdefault(normalize(req[0]), Declared(req[0], req[1], f"{scan.path} (!pip install)"))

    deps = []
    usages = _collect_usages(scans)
    for top in sorted(usages, key=str.lower):
        uses = usages[top]
        common = {"module": top, "kinds": tuple(sorted({k for _, _, k in uses})),
                  "locations": tuple(f"{p}:{line}" for p, line, _ in uses)}
        if top in REMOVED_STDLIB:
            deps.append(_removed(top, common))
        elif top in STDLIB and _module_exists("", top, files):
            deps.append(Dependency(category="local", **common,
                                   note="имя совпадает с модулем стандартной библиотеки — Python возьмёт файл проекта"))
        elif top in STDLIB:
            deps.append(Dependency(category="stdlib", **common))
        elif any(is_local(top, path, files) for path, _, _ in uses):
            deps.append(Dependency(category="local", **common))
        else:
            resolved = _resolve_package(top, declared, use_local_env)
            version, source = _version(resolved["package"], declared, use_local_env, top)
            deps.append(Dependency(category="external", version=version, version_source=source,
                                   **resolved, **common))

    packages = ({normalize(d.package) for d in deps if d.package}
                | {normalize(d.module) for d in deps if d.category == "external"})
    deps += _implicit(scans, packages, declared, use_local_env)
    for key, item in declared.items():
        if key not in packages:
            deps.append(Dependency(module=item.name, category="declared_only", package=item.name,
                                   status="объявлено в проекте", version=item.spec,
                                   version_source=item.source, locations=(item.source,),
                                   note="объявлено, но import не найден (плагин, бэкенд или лишняя зависимость)"))
    return deps
