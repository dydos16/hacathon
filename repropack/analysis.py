"""Сводный анализ проекта: зависимости + список предупреждений + кандидаты точки входа."""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .classify import PYTHON2, REMOVED_STDLIB, STDLIB_ADDED, Dependency, classify, parse_declared
from .scanner import DATA_EXTENSIONS, FileScan, scan_notebook, scan_source
from .secrets import SecretHit, find_secrets, is_secret_file

DEFAULT_PYTHON = (3, 11)
NO_REQUIREMENT = (3, 6)
ENTRY_NAMES = ("main.py", "run.py", "app.py", "analysis.py", "experiment.py", "train.py")
LEVEL_ORDER = {"high": 0, "medium": 1, "info": 2}


@dataclass(frozen=True)
class Issue:
    level: str    # high — воспроизведение сломается; medium — нужно решение человека; info — к сведению
    title: str
    detail: str
    where: str = ""


@dataclass(frozen=True)
class Analysis:
    files: dict[str, bytes]
    scans: tuple[FileScan, ...]
    dependencies: tuple[Dependency, ...]
    issues: tuple[Issue, ...]
    entry_candidates: tuple[str, ...]
    suggested_python: str
    python_reason: str
    secret_files: tuple[str, ...]
    secrets: tuple[SecretHit, ...]
    data_found: tuple[str, ...]
    data_missing: tuple[tuple[str, str], ...]
    hygiene: tuple[tuple[str, bool], ...]


def decode(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="replace")


def _scan_all(files: dict[str, bytes]) -> list[FileScan]:
    scans = []
    for path, data in sorted(files.items()):
        if path.endswith(".py"):
            scans.append(scan_source(path, decode(data)))
        elif path.endswith(".ipynb"):
            scans.append(scan_notebook(path, decode(data)))
    return scans


def _entry_candidates(scans: list[FileScan]) -> tuple[str, ...]:
    def rank(scan: FileScan) -> tuple:
        name = PurePosixPath(scan.path).name
        return (not scan.has_main_guard, name not in ENTRY_NAMES, scan.path.count("/"),
                scan.path.endswith(".ipynb"), name.startswith("test"), scan.path)
    runnable = [s for s in scans if not PurePosixPath(s.path).name.startswith("__")]
    return tuple(s.path for s in sorted(runnable, key=rank))


def _parse_version(text: str) -> tuple[int, int] | None:
    match = re.search(r"(\d+)\.(\d+)", text)
    return (int(match.group(1)), int(match.group(2))) if match else None


def _suggest_python(scans: list[FileScan], deps: list[Dependency], hint: str) -> tuple[str, str]:
    syntax_min = max((s.min_python for s in scans), default=NO_REQUIREMENT)
    stdlib_min = max((STDLIB_ADDED[d.module] for d in deps if d.module in STDLIB_ADDED), default=NO_REQUIREMENT)
    required = max(syntax_min, stdlib_min)
    chosen = max(DEFAULT_PYTHON, required)
    reasons = [f"по коду нужен ≥ {required[0]}.{required[1]}" if required > NO_REQUIREMENT
               else "современная стабильная версия; особых требований в коде не найдено"]
    declared = _parse_version(hint)
    if declared:
        is_lower_bound = hint.strip().startswith((">", "^", "~"))
        chosen = max(chosen, declared) if is_lower_bound else max(declared, required)
        reasons.append(f"в проекте указано «{hint}»")
    removed = [REMOVED_STDLIB[d.module][0] for d in deps
               if d.category == "removed" and REMOVED_STDLIB[d.module][0] != PYTHON2]
    if removed:
        ceiling = min(removed)
        chosen = min(chosen, (ceiling[0], ceiling[1] - 1))
        reasons.append(f"используются модули, удалённые в {ceiling[0]}.{ceiling[1]}")
    return f"{chosen[0]}.{chosen[1]}", "; ".join(reasons)


def _resolve_data(ref: str, importer: str, files: dict[str, bytes]) -> str | None:
    for base in (PurePosixPath(importer).parent, PurePosixPath(".")):
        candidate = str(PurePosixPath(base, ref.replace("\\", "/")))
        if candidate in files:
            return candidate
    return None


def _data_refs(scans: list[FileScan], files: dict[str, bytes]) -> tuple[list[str], list[tuple[str, str]]]:
    found, missing = set(), {}
    for scan in scans:
        for ref, line in scan.data_refs:
            if any(ch in ref for ch in "*{}<>|"):
                continue
            resolved = _resolve_data(ref, scan.path, files)
            if resolved:
                found.add(resolved)
            else:
                missing.setdefault(ref, f"{scan.path}:{line}")
    return sorted(found), sorted(missing.items())


def _relative_import_issues(scans: list[FileScan], files: dict[str, bytes]) -> list[Issue]:
    issues = []
    for scan in scans:
        for ref in scan.imports:
            if ref.kind != "relative" or not ref.module:
                continue
            base = PurePosixPath(scan.path).parent
            for _ in range(ref.level - 1):
                base = base.parent
            target = str(PurePosixPath(base, *ref.module.split(".")))
            if f"{target}.py" not in files and not any(p.startswith(f"{target}/") for p in files):
                issues.append(Issue("high", f"Относительный импорт «{'.' * ref.level}{ref.module}» не найден",
                                    "модуля нет в загруженных файлах — добавьте его в архив",
                                    f"{scan.path}:{ref.line}"))
    return issues


FINDING_ISSUES = {
    "syntax_error": ("high", "Файл не разбирается как Python 3",
                     "{detail}. Возможно, это код Python 2 или опечатка — импорты из файла не учтены"),
    "dynamic_unresolved": ("high", "Динамический импорт с вычисляемым именем",
                           "importlib/__import__ получает выражение «{detail}» — какой модуль загрузится, "
                           "статически не определить. Добавьте зависимость вручную"),
    "dynamic_import": ("medium", "Динамический импорт «{detail}»",
                       "модуль загружается через importlib — учтён в зависимостях, но проверьте"),
    "absolute_path": ("high", "Абсолютный путь «{detail}»",
                      "такой путь есть только на компьютере автора — замените на относительный"),
    "unseeded_random": ("medium", "Случайные числа без фиксированного seed",
                        "результат будет меняться от запуска к запуску — зафиксируйте, например, "
                        "np.random.default_rng(42) или random.seed(42)"),
    "cli_args": ("info", "Скрипт читает аргументы командной строки",
                 "укажите аргументы запуска — они попадут в README и verify.sh"),
    "notebook_magic": ("info", "В ноутбуке есть !pip install",
                       "пакеты «{detail}» учтены как объявленные зависимости"),
}


def _mask_path(p: str) -> str:
    # /Users/ivan/raw_2024.csv → /Users/***/raw_2024.csv
    parts = p.replace("\\", "/").split("/")
    if len(parts) > 2:
        parts[-2] = "***"
    return "/".join(parts)

def _finding_issues(scans: list[FileScan]) -> list[Issue]:
    issues = []
    for scan in scans:
        for f in scan.findings:
            level, title, detail = FINDING_ISSUES[f.code]
            where = f"{scan.path}:{f.line}" if f.line else scan.path
            shown = _mask_path(f.detail) if f.code == "absolute_path" else f.detail
            issues.append(Issue(level, title.format(detail=shown), detail.format(detail=shown), where))
    return issues


def _dependency_issues(deps: list[Dependency]) -> list[Issue]:
    issues = []
    for d in deps:
        where = ", ".join(d.locations[:3])
        if d.category == "removed":
            removed_in, replacement = REMOVED_STDLIB.get(d.module, (PYTHON2, ""))
            if removed_in != PYTHON2 and py < removed_in:
                # На предложенном Python модуль ещё есть — это не «критично», а «к сведению».
                issues.append(Issue("info", f"«{d.module}» устаревает",
                                    f"модуль удалён из Python {removed_in[0]}.{removed_in[1]}, "
                                    f"но на предложенном Python {python_version} ещё доступен",
                                    where))
                continue
            fix = f"замена с PyPI: {d.package}" if d.package else "перепишите код или используйте старый Python"
            issues.append(Issue("high", f"«{d.module}»: {d.note}", fix, where))
        elif d.needs_confirmation:
            detail = f"{d.note}. Варианты: {', '.join(d.candidates)}" if d.candidates else d.note
            issues.append(Issue("medium", f"Подтвердите пакет для «{d.module}»", detail, where))
        if "optional" in d.kinds and d.category == "external":
            issues.append(Issue("info", f"Необязательный импорт «{d.module}»",
                                "стоит в try/except ImportError — код работает и без пакета", where))
        if "conditional" in d.kinds and d.category == "external":
            issues.append(Issue("info", f"Условный импорт «{d.module}»",
                                "импортируется внутри if — нужен не во всех сценариях", where))
        if d.category == "declared_only":
            issues.append(Issue("info", f"«{d.package}» объявлен, но не импортируется", d.note, where))
        if d.category == "local" and d.note:
            issues.append(Issue("medium", f"Локальный «{d.module}» совпадает по имени со стандартным модулем",
                                f"{d.note}; если нужен стандартный модуль — переименуйте файл", where))
    unknown = sorted({d.package for d in deps if d.package and not d.version}, key=str.lower)
    if unknown:
        issues.append(Issue("medium", f"Версии неизвестны: {', '.join(unknown)}",
                            "по исходному коду версию не восстановить. Укажите версии вручную, разрешите чтение "
                            "локальной среды или зафиксируйте после проверки (verify.sh сохранит "
                            "requirements.lock.txt)"))
    return issues


def _hygiene(files: dict[str, bytes], data_found: list[str]) -> tuple[tuple[str, bool], ...]:
    names = [PurePosixPath(p).name.lower() for p in files]
    return (
        ("README автора", any(n.startswith("readme") for n in names)),
        ("LICENSE", any(n.startswith(("license", "licence", "copying")) for n in names)),
        ("Пример входных данных", bool(data_found) or any(p.lower().endswith(DATA_EXTENSIONS) for p in files)),
        ("Тесты", any(n.startswith("test_") or "/tests/" in f"/{p}" for n, p in zip(names, files))),
        ("Список зависимостей автора", bool(parse_declared(files)[0])),
    )


def _secret_issues(secret_files: tuple[str, ...], secrets: tuple[SecretHit, ...]) -> list[Issue]:
    issues = [Issue("high", "Файл с секретами исключён из пакета",
                    "не передавайте его коллегам; опишите нужные переменные в README", p) for p in secret_files]
    issues += [Issue("high", f"Похоже на секрет: {h.kind} ({h.masked})",
                     "в пакете значение заменено на <REDACTED> — передавайте его через переменную окружения",
                     f"{h.path}:{h.line}") for h in secrets]
    return issues


def analyze(files: dict[str, bytes], use_local_env: bool = False) -> Analysis:
    scans = _scan_all(files)
    deps = classify(scans, files, use_local_env)
    python, python_reason = _suggest_python(scans, deps, parse_declared(files)[1])
    secret_files = tuple(p for p in files if is_secret_file(p))
    secrets = tuple(hit for p, data in files.items() if p not in secret_files
                    for hit in find_secrets(p, decode(data)))
    data_found, data_missing = _data_refs(scans, files)
    hygiene = _hygiene(files, data_found)

    issues = _finding_issues(scans) + _relative_import_issues(scans, files) + _dependency_issues(deps, python)
    issues += _secret_issues(secret_files, secrets)
    issues += [Issue("high", f"Файл данных «{ref}» не найден",
                     "приложите пример данных или опишите в README, где его взять "
                     "(если это файл, который скрипт сам создаёт, — пропустите)", where)
               for ref, where in data_missing]
    if sum(s.has_main_guard for s in scans) > 1:
        issues.append(Issue("info", "Несколько точек входа", "выберите, какой файл запускать"))
    issues += [Issue("info", f"Нет: {name}", "не обязательно, но помогает повторить эксперимент")
               for name, present in hygiene if not present]

    return Analysis(
        files=files, scans=tuple(scans), dependencies=tuple(deps),
        issues=tuple(sorted(issues, key=lambda i: LEVEL_ORDER[i.level])),
        entry_candidates=_entry_candidates(scans), suggested_python=python, python_reason=python_reason,
        secret_files=secret_files, secrets=secrets, data_found=tuple(data_found),
        data_missing=tuple(data_missing), hygiene=hygiene,
    )

def test_removed_module_is_info_when_python_still_has_it():
    """cgi удалён в 3.13, но если предложен 3.11 — это info, а не high."""
    analysis = analyze({"a.py": b"import cgi\n"})
    assert analysis.suggested_python == "3.11"
    assert any(i.level == "info" and "cgi" in i.title for i in analysis.issues)
    assert not any(i.level == "high" and "cgi" in i.title for i in analysis.issues)
