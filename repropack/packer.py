"""Сборка пакета: requirements.txt, README, Dockerfile, отчёт, verify-скрипты → ZIP."""

import io
import json
import re
import shlex
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import __version__
from .analysis import Analysis, decode
from .classify import Dependency, normalize
from .secrets import redact

TEMPLATES = Environment(loader=FileSystemLoader(Path(__file__).parent / "data" / "templates"),
                        keep_trailing_newline=True, undefined=StrictUndefined, autoescape=False)
CATEGORIES = {"stdlib": "стандартная библиотека", "removed": "удалён из Python", "local": "локальный модуль",
              "external": "внешний пакет", "implicit": "неявная зависимость", "declared_only": "объявлен автором"}
LEVELS = {"high": "критично", "medium": "нужно решение", "info": "к сведению"}
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?$")
VERSION_SPEC = re.compile(r"^[A-Za-z0-9.*+!<>=~, -]*$")
VERSION_OPERATORS = ("==", ">=", "<=", "~=", "!=", ">", "<")
NOTEBOOK_RUNNERS = ("nbconvert", "ipykernel")
PACKAGED_CATEGORIES = ("external", "implicit", "declared_only", "removed")


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
    if not PACKAGE_NAME.match(req.package):
        raise ValueError(f"Некорректное имя пакета: {req.package!r}")
    if not VERSION_SPEC.match(req.version):
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
        if req.comment:
            notes.append(" ".join(req.comment.split()))
        line = f"{req.package}{spec}"
        lines.append(f"{line:<32} # {'; '.join(notes)}" if notes else line)
    return "\n".join(lines) + "\n"


def run_parts(entry_point: str, run_args: str) -> list[str]:
    if entry_point.endswith(".ipynb"):
        return ["-m", "nbconvert", "--to", "notebook", "--execute", entry_point, "--output", "executed.ipynb"]
    try:
        return [entry_point, *shlex.split(run_args)]
    except ValueError as exc:
        raise ValueError(f"Аргументы запуска не разобрать (незакрытая кавычка?): {run_args!r}") from exc


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "project"


def _context(analysis: Analysis, options: PackOptions, reqs: tuple[Requirement, ...], created: str) -> dict:
    parts = run_parts(options.entry_point, options.run_args)
    run_tail = shlex.join(parts)
    return {
        "project_name": options.project_name, "slug": slugify(options.project_name), "created": created,
        "python_version": options.python_version, "python_reason": analysis.python_reason,
        "requirements": reqs, "unknown_versions": [r.package for r in reqs if not _spec(r.version)],
        "run_tail": run_tail, "run_command": f"python {run_tail}", "cmd_json": json.dumps(["python", *parts]),
        "data_found": analysis.data_found, "data_missing": analysis.data_missing,
        "excluded": analysis.secret_files, "redacted": bool(analysis.secrets),
        "key_issues": [i for i in analysis.issues if i.level != "info"], "issues": analysis.issues,
        "dependencies": analysis.dependencies, "hygiene": analysis.hygiene,
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
    }, ensure_ascii=False, indent=2)


def render_package(analysis: Analysis, options: PackOptions, created: str | None = None) -> dict[str, str]:
    """Сгенерированные файлы пакета (без исходников) — для предпросмотра в интерфейсе и для ZIP."""
    created = created or datetime.now(timezone.utc).isoformat(timespec="seconds")
    reqs = _with_notebook_runners(options)
    ctx = _context(analysis, options, reqs, created)
    rendered = {name: TEMPLATES.get_template(f"{name}.j2").render(ctx)
                for name in ("README.md", "REPORT.md", "Dockerfile", "verify.sh", "verify.ps1")}
    return {**rendered, "requirements.txt": requirements_text(reqs, created),
            "repro.json": _manifest(analysis, options, reqs, ctx)}


def _project_files(analysis: Analysis) -> dict[str, bytes]:
    """Исходники для пакета: без файлов-секретов, с замаскированными секретами в тексте."""
    with_secrets = {h.path for h in analysis.secrets}
    return {path: redact(decode(data)).encode() if path in with_secrets else data
            for path, data in analysis.files.items() if path not in analysis.secret_files}


def build_zip(analysis: Analysis, options: PackOptions) -> bytes:
    if options.entry_point not in analysis.files:
        raise ValueError(f"Точка входа {options.entry_point!r} не найдена в проекте")
    root = f"{slugify(options.project_name)}-repro"
    generated = {name: text.encode("utf-8-sig" if name.endswith(".ps1") else "utf-8")
                 for name, text in render_package(analysis, options).items()}
    entries = {**{f"project/{p}": data for p, data in _project_files(analysis).items()}, **generated}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(f"{root}/{name}", date_time=datetime.now().timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if name == "verify.sh" else 0o644) << 16
            archive.writestr(info, data)
    return buffer.getvalue()
