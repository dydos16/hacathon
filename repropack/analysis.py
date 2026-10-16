"""Сводный анализ проекта: зависимости + список предупреждений + кандидаты точки входа."""

import platform
import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .classify import (NOT_ON_PYPI, PACKAGED_CATEGORIES, PYTHON2, REMOVED_STDLIB, STDLIB_ADDED, Dependency, classify,
                       parse_declared_checked)
from .markdown import escape
from .scanner import DATA_EXTENSIONS, NO_REQUIREMENT, FileScan, scan_notebook, scan_source, skipped_scan
from .secrets import SecretHit, env_names, file_text, find_secrets, is_secret_file, redact

DEFAULT_PYTHON = (3, 11)
ENTRY_NAMES = ("main.py", "run.py", "app.py", "analysis.py", "experiment.py", "train.py")
LEVEL_ORDER = {"high": 0, "medium": 1, "info": 2}
UNRESOLVABLE_DATA = "*{}<>|%"  # шаблоны имён (glob, %-формат): конкретный файл по ним не найти
PYTHON_CLAUSE = re.compile(r"(\^|~=|~|===|==|!=|<=|>=|<|>)?\s*(\d+)(?:\.(\d+))?(?:\.[\d*]+)*")
MAX_TOTAL_CODE_CHARS = 10_000_000  # весь проект: крошечный ZIP с мегабайтами кода не должен занимать сервер минутами
# Управляющие символы и смена направления текста из загрузки (имя модуля, путь) не попадают в отчёт, README и
# терминал: перевод строки дописал бы в REPORT.md свой заголовок, а ESC-последовательность — сменила бы заголовок окна
UNSAFE_CHARS = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
CONDA_ONLY_SHOWN = 8
PLACES_SHOWN = 3
AUXILIARY_PATH = re.compile(r"(^|/)((setup|conftest|noxfile)\.py|test_[^/]*|[^/]*_test\.py)$"
                            r"|(^|/)(tests?|docs?|migrations)/")


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
    environment: tuple[tuple[str, str], ...] = ()  # среда, где запущен анализ; только с согласия пользователя


def local_environment() -> tuple[tuple[str, str], ...]:
    """Версия Python и ОС этой машины — для отчёта о среде. Путей и имени пользователя здесь нет."""
    return ("Python", platform.python_version()), ("ОС", platform.platform(terse=True))


def decode(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="replace")


def _scan_all(files: dict[str, bytes]) -> list[FileScan]:
    scans, budget = [], MAX_TOTAL_CODE_CHARS
    for path, data in sorted(files.items()):
        if path.endswith(".py"):
            text = decode(data)
            budget -= len(text)
            scans.append(scan_source(path, text) if budget >= 0 else
                         skipped_scan(path, f"исчерпан лимит {MAX_TOTAL_CODE_CHARS // 1_000_000} МБ кода на проект"))
        elif path.endswith(".ipynb"):
            scans.append(scan_notebook(path, decode(data)))
    return scans


def clean(text: str) -> str:
    """Текст из загрузки для отчёта: без управляющих символов и без секретов (их значения → <REDACTED>)."""
    return redact(UNSAFE_CHARS.sub(" ", text))


def is_auxiliary(path: str) -> bool:
    """Тесты, setup.py, conftest.py, документация, миграции — не то, что запускают для эксперимента."""
    return bool(AUXILIARY_PATH.search(path))


def _imported_modules(scans: list[FileScan]) -> set[str]:
    """Что импортирует сам проект; импорты из тестов не в счёт — тесты импортируют и главный скрипт."""
    return {ref.module for scan in scans if not is_auxiliary(scan.path) for ref in scan.imports if ref.module}


def _is_imported(path: str, imported: set[str]) -> bool:
    """Файл, который импортируют другие файлы проекта, — библиотека, а не скрипт («model.py» для «train.py»)."""
    dotted = "." + PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")
    return any(dotted.endswith(f".{module}") for module in imported)


def _entry_candidates(scans: list[FileScan]) -> tuple[str, ...]:
    imported = _imported_modules(scans)

    def rank(scan: FileScan) -> tuple:
        runs_itself = scan.has_main_guard or any(f.code == "cli_args" for f in scan.findings)
        return (is_auxiliary(scan.path), _is_imported(scan.path, imported), not runs_itself,
                PurePosixPath(scan.path).name not in ENTRY_NAMES, scan.path.count("/"),
                scan.path.endswith(".ipynb"), scan.path)
    runnable = [s for s in scans if not PurePosixPath(s.path).name.startswith("__")]
    return tuple(s.path for s in sorted(runnable, key=rank))


def _python_range(hint: str) -> tuple[tuple[int, int] | None, tuple[int, int] | None]:
    """Нижняя и верхняя (включительно) границы версии Python из «>=3.8,<3.11», «^3.10», «3.10.13»…"""
    low = high = None
    for operator, major, minor in PYTHON_CLAUSE.findall(hint[:200]):  # длинная строка из пробелов — ReDoS
        version = (int(major), int(minor or 0))
        if operator in ("", "==", "===", ">=", ">", "~=", "~", "^"):
            low = max(low or version, version)
        if (operator in ("", "==", "===", "~") and minor) or operator == "<=":
            high = min(high or version, version)
        elif operator == "<":
            high = min(high or version, (version[0], version[1] - 1))
    return low, high


def _version(version: tuple[int, int]) -> str:
    return f"{version[0]}.{version[1]}"


def _removed_conflict(blocking: list[str], required: tuple[int, int]) -> list[Issue]:
    """Коду нужен новый Python, а часть модулей в нём уже удалена: одной версии, где работает всё, нет."""
    if not blocking:
        return []
    lost = ", ".join(f"«{m}»" for m in blocking if not REMOVED_STDLIB[m][1])
    fix = (f"Замените в коде: {lost}" if lost
           else "модули дадут пакеты-замены из requirements.txt — проверьте запуск через verify.sh")
    names = ", ".join(f"«{m}»" for m in blocking)
    return [Issue("high" if lost else "medium", "Коду нужны несовместимые версии Python",
                  f"синтаксис или модули кода требуют Python ≥ {_version(required)}, а {names} в нём уже нет. "
                  f"Выбрана {_version(required)}: на более старой код даже не разберётся. {fix}")]


def _suggest_python(scans: list[FileScan], deps: list[Dependency], hint: str) -> tuple[str, str, list[Issue]]:
    """Версия Python, причина выбора и противоречия, если одной версии на всё нет: о них говорим, а не молчим."""
    syntax_min = max((s.min_python for s in scans), default=NO_REQUIREMENT)
    stdlib_min = max((STDLIB_ADDED[d.module] for d in deps if d.module in STDLIB_ADDED), default=NO_REQUIREMENT)
    required = max(syntax_min, stdlib_min)
    chosen = max(DEFAULT_PYTHON, required)
    reasons = [f"по коду нужен ≥ {_version(required)}"] if required > NO_REQUIREMENT else []
    issues = []
    low, high = _python_range(hint)
    if low or high:
        lifted = max(chosen, low or chosen)
        chosen = max(min(lifted, high or lifted), required)  # синтаксис кода важнее объявленной автором границы
        reasons.append(f"в проекте указано «{escape(hint)}»")
    removed = sorted((REMOVED_STDLIB[d.module][0], d.module) for d in deps
                     if d.category == "removed" and REMOVED_STDLIB[d.module][0] != PYTHON2)
    removed_note = ""
    if removed:
        (major, minor), module = removed[0]
        removed_note = f"«{module}» удалён в {major}.{minor}"
        issues += _removed_conflict([m for version, m in removed if version <= required], required)
        chosen = max(min(chosen, (major, minor - 1)), required)  # код, который не разбирается, не запустится вовсе
        reasons.append(f"используются модули, удалённые в {major}.{minor}")
    conflict = (f"код требует ≥ {_version(required)}" if high and chosen > high
                else removed_note if low and chosen < low else "")
    if conflict:
        issues.append(Issue("medium", "Версия Python расходится с объявленной в проекте",
                            f"в проекте указано «{escape(hint)}», но {conflict} — выбрана {_version(chosen)}. "
                            "Исправьте объявление или код"))
    reason = "; ".join(reasons) or "современная стабильная версия; особых требований в коде не найдено"
    return _version(chosen), reason, issues


def _resolve_data(ref: str, importer: str, files: dict[str, bytes]) -> str | None:
    """Путь от папки скрипта или от корня проекта; иначе — файл с тем же «хвостом» пути в любой папке.

    Так находятся пути, собранные через os.path.join(DATA_DIR, "x.csv") или Path(...) / "x.csv".
    """
    ref = ref.replace("\\", "/")
    for base in (posixpath.dirname(importer), ""):
        candidate = posixpath.normpath(posixpath.join(base, ref))
        if candidate in files:
            return candidate
    tail = "/" + "/".join(part for part in PurePosixPath(ref).parts if part not in ("..", ".", "/"))
    return next((path for path in sorted(files) if f"/{path}".endswith(tail)), None)


def _data_refs(scans: list[FileScan], files: dict[str, bytes]) -> tuple[list[str], list[tuple[str, str]]]:
    found, missing = set(), {}
    for scan in scans:
        for ref, line in scan.data_refs:
            if any(ch in ref for ch in UNRESOLVABLE_DATA):
                continue
            resolved = _resolve_data(ref, scan.path, files)
            if resolved:
                found.add(resolved)
            else:
                missing.setdefault(ref, scan.where(line))
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
                                    "модуля нет в загруженных файлах — добавьте его в архив", scan.where(ref.line)))
    return issues


FINDING_ISSUES = {
    "syntax_error": ("high", "Файл не разбирается как Python 3",
                     "{detail}. Возможно, это код Python 2 или опечатка — импорты из файла не учтены"),
    "too_large": ("high", "Файл слишком большой для разбора",
                  "{detail}: разбираются файлы до 1 МБ кода и до 10 МБ на проект — импорты из файла не учтены, "
                  "проверьте их вручную"),
    "too_complex": ("high", "Файл слишком сложный для разбора",
                    "{detail} — импорты из файла не учтены, проверьте их вручную"),
    "long_statement": ("info", "Очень длинное выражение пропущено при разборе",
                       "строка слишком длинная для парсера Python (обычно это сгенерированная формула) — "
                       "остальной файл разобран, но импорты и пути к данным внутри этой строки не учтены"),
    "cell_syntax_error": ("medium", "Ячейка ноутбука не разбирается как Python",
                          "{detail}: возможно, это синтаксис IPython (`x = !ls`, `obj?`) — импорты из ячейки "
                          "не учтены, а запуск ноутбука через nbconvert может на ней остановиться"),
    "dynamic_unresolved": ("high", "Динамический импорт с вычисляемым именем",
                           "`importlib`/`__import__` получает выражение «{detail}» — какой модуль загрузится, "
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
    "notebook_magic": ("info", "В ноутбуке ставятся пакеты (pip install)",
                       "пакеты «{detail}» учтены как объявленные зависимости"),
    "unseeded_split": ("medium", "train_test_split без random_state",
                       "разбиение на обучающую и тестовую выборки будет меняться от запуска к запуску — "
                       "передайте random_state=42"),
    "sys_path": ("info", "Код меняет sys.path",
                 "импорты из добавленных папок работают только при такой же структуре папок, как у автора, — "
                 "проверьте эти модули в таблице зависимостей"),
    "exec_import": ("medium", "Импорт «{detail}» внутри exec/eval",
                    "модуль загружается из строки кода — учтён в зависимостях, но проверьте"),
    "exec_unresolved": ("info", "Код выполняется через exec",
                        "строка «{detail}» собирается при запуске — импорты внутри неё статически не видны; "
                        "если они там есть, добавьте зависимости вручную"),
}


def _finding_issues(scans: list[FileScan]) -> list[Issue]:
    issues = []
    for scan in scans:
        for f in scan.findings:
            level, title, detail = FINDING_ISSUES[f.code]
            text = escape(f.detail)  # строка из кода: её символы не должны стать Markdown-разметкой
            issues.append(Issue(level, title.format(detail=text), detail.format(detail=text),
                                scan.where(f.line)))
    return issues


def _dependency_issues(deps: list[Dependency]) -> list[Issue]:
    issues = []
    for d in deps:
        where = ", ".join(d.locations[:3])
        if d.category == "removed":
            fix = f"замена с PyPI: {d.package}" if d.package else "перепишите код или используйте старый Python"
            issues.append(Issue("high", f"«{d.module}»: {d.note}", fix, where))
        elif d.status == NOT_ON_PYPI:
            issues.append(Issue("high", f"«{d.module}» не ставится из PyPI", d.note, where))
        elif d.needs_confirmation:
            detail = f"{d.note}. Варианты: {', '.join(d.candidates)}" if d.candidates else d.note
            issues.append(Issue("medium", f"Подтвердите пакет для «{d.module}»", detail, where))
        elif d.category == "external" and d.note:  # версии в файлах автора расходятся
            issues.append(Issue("medium", f"Версии «{d.package}» в файлах расходятся",
                                f"{d.note} — выбрана {d.version}; оставьте одну версию", where))
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
    return issues


def _summary_issues(deps: list[Dependency]) -> list[Issue]:
    issues = []
    unknown = sorted({d.package for d in deps if d.category in PACKAGED_CATEGORIES and d.package and not d.version},
                     key=str.lower)
    if unknown:
        issues.append(Issue("medium", f"Версии неизвестны: {', '.join(unknown)}",
                            "по исходному коду версию не восстановить. Укажите версии вручную, разрешите чтение "
                            "локальной среды или зафиксируйте после проверки (verify.sh сохранит "
                            "requirements.lock.txt)"))
    conda_only = [d for d in deps if d.category == "conda_only"]
    if conda_only:
        names = [d.package for d in conda_only]
        more = len(names) - CONDA_ONLY_SHOWN
        shown = ", ".join(names[:CONDA_ONLY_SHOWN]) + (f" и ещё {more}" if more > 0 else "")
        issues.append(Issue("info", f"Пакеты conda без import в коде: {len(names)}",
                            f"{shown} — в requirements.txt не включены: часто это системные библиотеки conda. "
                            "Если какой-то нужен коду (плагин, бэкенд), добавьте его в таблицу вручную",
                            conda_only[0].version_source))
    return issues


def _hygiene(files: dict[str, bytes], data_found: list[str], has_declared: bool) -> tuple[tuple[str, bool], ...]:
    names = [PurePosixPath(p).name.lower() for p in files]
    return (
        ("README автора", any(n.startswith("readme") for n in names)),
        ("LICENSE", any(n.startswith(("license", "licence", "copying")) for n in names)),
        ("Пример входных данных", bool(data_found) or any(p.lower().endswith(DATA_EXTENSIONS) for p in files)),
        ("Тесты", any(n.startswith("test_") or "/tests/" in f"/{p}" for n, p in zip(names, files))),
        ("Список зависимостей автора", has_declared),
    )


def _excluded_detail(path: str, data: bytes) -> str:
    names = env_names(path, decode(data))
    if names:
        return (f"коллеге нужны свои значения переменных {', '.join(names)}: они перечислены без значений "
                "в .env.example пакета — впишите значения и переименуйте файл в .env")
    return "если код читает этот файл, коллеге понадобится свой — передайте его отдельно, не в архиве"


def _secret_issues(files: dict[str, bytes], secret_files: tuple[str, ...],
                   secrets: tuple[SecretHit, ...]) -> list[Issue]:
    # Исключить файл — правильно, и автору исправлять нечего: это решение для коллеги, а не поломка
    issues = [Issue("medium", "Файл с секретами исключён из пакета", _excluded_detail(p, files[p]), p)
              for p in secret_files]
    issues += [Issue("high", f"Похоже на секрет: {h.kind} ({h.masked})",
                     "в пакете значение заменено на <REDACTED> — передавайте его через переменную окружения",
                     f"{h.path}:{h.line}") for h in secrets]
    return issues


def _merge_repeats(issues: list[Issue]) -> list[Issue]:
    """Одно и то же предупреждение из многих файлов — одной строкой со списком мест, а не десятком строк."""
    places: dict[tuple[str, str, str], list[str]] = {}
    for issue in issues:
        places.setdefault((issue.level, issue.title, issue.detail), []).append(issue.where)
    merged = []
    for (level, title, detail), wheres in places.items():
        unique = list(dict.fromkeys(w for w in wheres if w))
        more = len(unique) - PLACES_SHOWN
        merged.append(Issue(level, title, detail,
                            ", ".join(unique[:PLACES_SHOWN]) + (f" и ещё {more}" if more > 0 else "")))
    return merged


def _unreadable_declared(paths: tuple[str, ...]) -> list[Issue]:
    return [Issue("medium", f"Файл «{path}» не разобран",
                  "в нём некорректная или слишком большая запись зависимостей; проверьте её вручную в таблице", path)
            for path in paths]


def analyze(files: dict[str, bytes], use_local_env: bool = False) -> Analysis:
    scans = _scan_all(files)
    deps = classify(scans, files, use_local_env)
    declared, python_hint, unreadable = parse_declared_checked(files)
    python, python_reason, python_issues = _suggest_python(scans, deps, python_hint)
    secret_files = tuple(p for p in files if is_secret_file(p))
    secrets = tuple(hit for p, data in files.items() if p not in secret_files
                    for hit in find_secrets(p, file_text(data)[0]))
    data_found, data_missing = _data_refs(scans, files)
    data_missing = [(clean(ref), where) for ref, where in data_missing]
    hygiene = _hygiene(files, data_found, bool(declared))

    issues = python_issues + _finding_issues(scans) + _relative_import_issues(scans, files)
    issues += _unreadable_declared(unreadable)
    issues += _dependency_issues(deps) + _summary_issues(deps) + _secret_issues(files, secret_files, secrets)
    issues += [Issue("high", f"Файл данных «{escape(ref)}» не найден",
                     "приложите пример данных или опишите в README, где его взять "
                     "(если это файл, который скрипт сам создаёт, — пропустите)", where)
               for ref, where in data_missing]
    if sum(s.has_main_guard and not is_auxiliary(s.path) for s in scans) > 1:
        issues.append(Issue("info", "Несколько точек входа", "выберите, какой файл запускать"))
    issues += [Issue("info", f"Нет: {name}", "не обязательно, но помогает повторить эксперимент")
               for name, present in hygiene if not present]
    # Детали проблем берут куски кода (аргумент exec, имя модуля…): секрет в них не должен уйти в отчёт и интерфейс
    issues = [Issue(i.level, clean(i.title), clean(i.detail), i.where) for i in issues]

    return Analysis(
        files=files, scans=tuple(scans), dependencies=tuple(deps),
        issues=tuple(sorted(_merge_repeats(issues), key=lambda i: LEVEL_ORDER[i.level])),
        entry_candidates=_entry_candidates(scans), suggested_python=python, python_reason=python_reason,
        secret_files=secret_files, secrets=secrets, data_found=tuple(data_found),
        data_missing=tuple(data_missing), hygiene=hygiene,
        environment=local_environment() if use_local_env else (),
    )
