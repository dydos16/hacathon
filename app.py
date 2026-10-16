"""Streamlit-интерфейс: проект → итог со скачиванием → проблемы → зависимости → запуск → содержимое пакета."""

import hashlib
import io
import zipfile
from pathlib import Path, PurePosixPath

import pandas as pd
import streamlit as st

from repropack.analysis import ENTRY_NAMES, Analysis, Issue, analyze, is_auxiliary
from repropack.classify import Dependency
from repropack.intake import IntakeError, read_directory, read_upload
from repropack.packer import (CATEGORIES, PACKAGE_NAME, VERSION_SPEC, PackOptions, Requirement, build_zip,
                              default_requirements, packaged_dependencies, slugify)
from repropack.scanner import FileScan

EXAMPLES = {
    "numpy_pandas_script": "Скрипт с numpy/pandas и CSV-данными",
    "local_module_project": "Скрипт с локальным модулем (без внешних пакетов)",
    "messy_lab_project": "«Сырой» проект: секреты, динамические импорты, пропавшие данные",
}
EXAMPLES_DIR = Path(__file__).parent / "examples"
PYTHON_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13"]
# Уровень → заголовок группы и цвет текста (цвет вместо значков: красный — только для критичного)
LEVEL_LABELS = {"high": ("Критично", "red"), "medium": ("Нужно решение", "orange"), "info": ("К сведению", "gray")}
ISSUES_BEFORE_SCROLL = 8
ISSUE_LIST_HEIGHT = 420  # px: длинный список прокручивается внутри своей группы
START_SCREEN = (
    ("Что загрузить", "Файлы `.py` и `.ipynb` или ZIP всего проекта, до 20 МБ. Данные и `requirements.txt` "
                      "можно приложить рядом."),
    ("Что получите", "ZIP: `requirements.txt` с пояснением к каждой строке, README с командами, Dockerfile, "
                     "`verify.sh` / `verify.ps1` и отчёт о том, что определить не удалось."),
    ("Код не запускается", "Только статический разбор (`ast`) в памяти, на диск ничего не сохраняется. "
                           "Файлы с секретами исключаются, ключи в коде заменяются на `<REDACTED>`."),
)
# Видимые колонки таблицы; «Комментарий» скрыт, но нужен: он попадает в requirements.txt
TABLE_COLUMNS = ["Включить", "Модуль", "Пакет PyPI", "Версия", "Подтверждено", "Примечание"]
LOCKED_COLUMNS = ["Модуль", "Примечание", "Комментарий"]
# Ячейки проверяются тем же regex, что и при сборке: неверное значение не принимается ещё в таблице
EDITOR_COLUMNS = {
    "Включить": st.column_config.CheckboxColumn(default=True),
    "Пакет PyPI": st.column_config.TextColumn(required=True, validate=PACKAGE_NAME.pattern,
                                              help="имя на PyPI, например scikit-learn"),
    "Версия": st.column_config.TextColumn(validate=VERSION_SPEC.pattern, help="например 1.26.4 или >=2.0"),
    "Подтверждено": st.column_config.CheckboxColumn(default=True,
                                                    help="снимите, если не уверены, — в requirements.txt будет пометка"),
    "Примечание": st.column_config.TextColumn(help="откуда известно имя пакета и его версия"),
}
# Файлы пакета для предпросмотра → язык подсветки ("markdown" — показать как текст)
PREVIEW = {"README.md": "markdown", "requirements.txt": "text", "REPORT.md": "markdown", "Dockerfile": "dockerfile",
           "verify.sh": "bash", "verify.ps1": "powershell", "repro.json": "json"}
PREVIEW_HEIGHT = 480  # px: длинный отчёт прокручивается внутри вкладки, а не растягивает страницу

st.set_page_config(page_title="repro-packer", layout="wide")


@st.cache_data(show_spinner="Статический разбор кода…")
def cached_analysis(files: dict[str, bytes], use_local_env: bool) -> Analysis:
    return analyze(files, use_local_env)


def choose_source() -> tuple[dict[str, bytes], str] | None:
    mode = st.radio("Источник", ["Загрузить свой проект", "Демо-проект"], horizontal=True,
                    label_visibility="collapsed")
    if mode == "Демо-проект":
        name = st.selectbox("Демо-проект", EXAMPLES, format_func=lambda k: f"{k} — {EXAMPLES[k]}")
        return read_directory(EXAMPLES_DIR / name), name
    uploads = st.file_uploader("Файлы проекта: .py, .ipynb, ZIP-архив, данные и requirements",
                               accept_multiple_files=True)
    if not uploads:
        return None
    name = Path(uploads[0].name).stem if len(uploads) == 1 else "project"
    return read_upload([(u.name, u.getvalue()) for u in uploads]), name


def show_start_screen() -> None:
    for col, (title, text) in zip(st.columns(len(START_SCREEN)), START_SCREEN):
        col.markdown(f"**{title}**  \n{text}")


def show_verdict(analysis: Analysis) -> None:
    """Одна строка-ответ на главный вопрос: можно ли уже отдавать пакет коллеге."""
    high = sum(i.level == "high" for i in analysis.issues)
    medium = sum(i.level == "medium" for i in analysis.issues)
    if high:
        st.error(f"**Скорее всего, у коллеги не запустится.** Критичных проблем: {high} — исправьте их "
                 "по списку ниже и загрузите проект заново.")
    elif medium:
        st.warning(f"**Почти готово.** Пунктов, где нужно ваше решение: {medium} — проверьте список ниже "
                   "и таблицу зависимостей.")
    else:
        st.success("**Явных препятствий нет.** Скачайте пакет и проверьте его командой `verify.sh` "
                   "на чистой машине.")


def show_metrics(analysis: Analysis, requirements: tuple[Requirement, ...]) -> None:
    """Пакеты считаются по таблице: подтвердили или исключили строку — счётчики сразу пересчитаны."""
    with st.container(horizontal=True):  # на узком экране метрики переносятся, а не встают в столбик по одной
        st.metric("Файлов", len(analysis.files))
        st.metric("Внешних пакетов", len(requirements), help="включённые строки таблицы зависимостей — они "
                                                             "попадут в requirements.txt")
        st.metric("Критичных проблем", sum(i.level == "high" for i in analysis.issues))
        st.metric("Нужно подтвердить", sum(not r.confirmed for r in requirements),
                  help="пакеты без отметки «Подтверждено» в таблице зависимостей")


def unpack(package: bytes) -> tuple[list[str], dict[str, bytes]]:
    """Состав архива и сгенерированные файлы — из готового ZIP: показано ровно то, что будет скачано."""
    archive = zipfile.ZipFile(io.BytesIO(package))
    names = archive.namelist()
    root = names[0].split("/", 1)[0]
    return names, {name: archive.read(f"{root}/{name}") for name in PREVIEW}


def package_summary(analysis: Analysis) -> str:
    """Что из загрузки попадёт в архив, чего нет и что скрыто — без открытия REPORT.md."""
    facts = (("Данные в пакете", analysis.data_found),
             ("Нет в загрузке", [ref for ref, _ in analysis.data_missing]),
             ("Исключены (файлы с секретами)", analysis.secret_files),
             ("Секреты заменены на `<REDACTED>`", sorted({h.path for h in analysis.secrets})))
    return "  \n".join(f"**{label}:** {', '.join(f'`{p}`' for p in items)}" for label, items in facts if items)


def show_summary(analysis: Analysis, options: PackOptions, package: bytes | None, error: str) -> None:
    """Итог наверху страницы: вердикт, числа и скачивание — без прокрутки к концу."""
    show_verdict(analysis)
    show_metrics(analysis, options.requirements)
    if package is None:
        st.error(f"Пакет не собран: {error}")
        return
    names, generated = unpack(package)
    with st.container(horizontal=True):
        st.download_button("Скачать пакет (ZIP)", package, file_name=f"{names[0].split('/', 1)[0]}.zip",
                           mime="application/zip", type="primary")
        st.download_button("requirements.txt", generated["requirements.txt"], file_name="requirements.txt",
                           mime="text/plain")
        st.download_button("REPORT.md", generated["REPORT.md"], file_name="REPORT.md", mime="text/markdown")
    if summary := package_summary(analysis):
        st.markdown(summary)
    notes = ["У коллеги: распакуйте архив и запустите `sh verify.sh` (Windows: `verify.ps1`). Итог — в конце "
             "`verify_log.txt`, точные версии — в `requirements.lock.txt`."]
    if unconfirmed := [r.package for r in options.requirements if not r.confirmed]:
        notes.insert(0, f"Не подтверждены: {', '.join(unconfirmed)} — попадут в requirements.txt с пометкой.")
    st.caption("  \n".join(notes))


def issue_markdown(issue: Issue) -> str:
    """Что случилось и где — первой строкой, что сделать — второй."""
    where = f" · `{issue.where}`" if issue.where else ""
    return f"- **{issue.title}**{where}  \n  → {issue.detail}"


def show_issues(analysis: Analysis) -> None:
    st.subheader("Что мешает воспроизвести")
    if not analysis.issues:
        st.caption("Проблем не найдено.")
    for level, (label, color) in LEVEL_LABELS.items():
        issues = [i for i in analysis.issues if i.level == level]
        if not issues:
            continue
        height = ISSUE_LIST_HEIGHT if len(issues) > ISSUES_BEFORE_SCROLL else "content"
        with st.expander(f":{color}[{label}: {len(issues)}]", expanded=level != "info"), st.container(height=height):
            st.markdown("\n".join(map(issue_markdown, issues)))


def _cell(row: pd.Series, column: str) -> str:
    value = row.get(column)
    return "" if value is None or pd.isna(value) else str(value).strip()


def _flag(row: pd.Series, column: str) -> bool:
    """Пустая ячейка в строке, добавленной вручную, считается «да»."""
    value = row.get(column)
    return True if value is None or pd.isna(value) else bool(value)


def dependency_note(d: Dependency) -> str:
    """Откуда известно имя пакета и версия — одной строкой вместо четырёх колонок."""
    origin = d.status if d.category == "external" else CATEGORIES[d.category]
    if d.candidates:
        origin += f": {' / '.join(d.candidates)}"
    return origin + (f" · версия: {d.version_source}" if d.version_source else "")


def show_all_modules(analysis: Analysis) -> None:
    deps = analysis.dependencies
    stdlib, local = (sum(d.category == c for d in deps) for c in ("stdlib", "local"))
    with st.expander(f"Все модули проекта: {len(deps)} · стандартная библиотека: {stdlib} · локальные: {local}"):
        st.dataframe(pd.DataFrame([{"Модуль": d.module, "Категория": CATEGORIES[d.category],
                                    "Пакет PyPI": d.package, "Где": ", ".join(d.locations[:3])} for d in deps]),
                     width="stretch", hide_index=True)


def dependency_editor(analysis: Analysis, key: str) -> tuple[Requirement, ...]:
    st.subheader("Зависимости")
    st.caption("Исправьте имя пакета или версию, снимите «Включить» у лишнего, отметьте «Подтверждено». "
               "Строки, где нужно решение, — сверху; строку можно добавить вручную.")
    pairs = sorted(zip(packaged_dependencies(analysis), default_requirements(analysis)),
                   key=lambda pair: not pair[0].needs_confirmation)
    rows = pd.DataFrame([{
        "Включить": True, "Модуль": d.module, "Пакет PyPI": r.package, "Версия": r.version,
        "Подтверждено": r.confirmed, "Примечание": dependency_note(d), "Комментарий": r.comment,
    } for d, r in pairs], columns=[*TABLE_COLUMNS, "Комментарий"])
    if rows.empty:
        st.caption("Внешних пакетов не найдено: requirements.txt будет без пакетов.")
    edited = st.data_editor(rows, key=key, num_rows="dynamic", width="stretch", hide_index=True,
                            column_order=TABLE_COLUMNS, disabled=LOCKED_COLUMNS, column_config=EDITOR_COLUMNS)
    show_all_modules(analysis)
    return tuple(
        Requirement(_cell(row, "Пакет PyPI"), _cell(row, "Версия"),
                    _cell(row, "Комментарий") if _cell(row, "Модуль") else "добавлено вручную",
                    _flag(row, "Подтверждено"))
        for _, row in edited.iterrows()
        if _flag(row, "Включить") and _cell(row, "Пакет PyPI")
    )


def entry_reason(scan: FileScan) -> str:
    if scan.path.endswith(".ipynb"):
        return "ноутбук выполнится целиком через `python -m nbconvert --execute`, аргументы ему не передаются"
    if scan.has_main_guard:
        return 'в файле есть `if __name__ == "__main__"`'
    if PurePosixPath(scan.path).name in ENTRY_NAMES:
        return "так обычно называют главный скрипт"
    return 'явных признаков нет (ни `if __name__ == "__main__"`, ни имени вроде `main.py`) — проверьте выбор'


def run_options(analysis: Analysis, name: str, project: str) -> tuple[str, str, str, str]:
    """Ключи виджетов привязаны к проекту: при смене точки входа ввод сохраняется, при смене проекта — сброс."""
    st.subheader("Как запускать")
    cols = st.columns([2, 1, 2, 2])
    entry = cols[0].selectbox("Точка входа", analysis.entry_candidates, key=f"entry-{project}",
                              help="Сначала файлы с `if __name__ == '__main__'` и типичными именами (main.py, run.py…)")
    scan = next(s for s in analysis.scans if s.path == entry)
    versions = sorted({*PYTHON_VERSIONS, analysis.suggested_python}, key=lambda v: tuple(map(int, v.split("."))))
    python = cols[1].selectbox("Python", versions, index=versions.index(analysis.suggested_python),
                               key=f"python-{project}")
    notebook = entry.endswith(".ipynb")
    needs_args = not notebook and any(f.code == "cli_args" for f in scan.findings)
    args = cols[2].text_input("Аргументы запуска", placeholder="--input data.csv" if needs_args else "",
                              disabled=notebook, key=f"args-{project}")
    project_name = cols[3].text_input("Название проекта", value=name, key=f"name-{project}").strip() or name
    cols[3].caption(f"Имя архива: `{slugify(project_name)}-repro.zip`"
                    + ("" if project_name.isascii() else " — нелатинские буквы в имя файла не попадают"))
    if is_auxiliary(entry):  # то же правило, по которому такие файлы стоят в конце списка
        st.warning(f"`{entry}` похож на тест или служебный файл — эксперимент обычно запускают другим скриптом.")
    notes = [f"Точка входа: {entry_reason(scan)}.",
             f"Python {analysis.suggested_python} предложен: {analysis.python_reason}."]
    if needs_args and not args:
        notes.append("Точка входа читает аргументы командной строки — при необходимости укажите их.")
    st.caption("  \n".join(notes))
    return entry, python, args, project_name


def show_preview(package: bytes) -> None:
    st.subheader("Содержимое пакета")
    names, generated = unpack(package)
    st.caption(f"Файлов в архиве: {len(names)} · {len(package) / 1024:.0f} КБ")
    tabs = st.tabs([*PREVIEW, "Состав архива"])
    for tab, (name, language) in zip(tabs, PREVIEW.items()):
        text = generated[name].decode("utf-8-sig")
        with tab, st.container(height=PREVIEW_HEIGHT):
            if language == "markdown":
                st.markdown(text)
            else:
                st.code(text, language=language)
    tabs[-1].code("\n".join(names), language="text")


def build(analysis: Analysis, options: PackOptions) -> tuple[bytes | None, str]:
    try:
        return build_zip(analysis, options), ""
    except ValueError as exc:
        return None, str(exc)


def main() -> None:
    st.title("repro-packer")
    st.markdown("Собирает из научного Python-проекта пакет, который коллега повторит у себя: `requirements.txt`, "
                "README, Dockerfile и скрипт проверки. Код проекта не запускается — только читается.")
    st.subheader("Проект")
    try:
        source = choose_source()
    except IntakeError as exc:
        st.error(f"Не удалось принять загрузку: {exc}")
        return
    use_local_env = st.checkbox("Читать версии пакетов из среды, где запущен repro-packer",
                                help="Только при локальном запуске: версии берутся из importlib.metadata этой "
                                     "машины. Без согласия версии не читаются.")
    if source is None:
        show_start_screen()
        return
    files, name = source
    analysis = cached_analysis(files, use_local_env)
    if not analysis.entry_candidates:
        st.error("Нечего запускать: в загрузке только служебные файлы Python (`__init__.py`, `__main__.py`…). "
                 "Добавьте скрипт или ноутбук, который проводит эксперимент.")
        return
    summary = st.container(border=True)  # заполняется в конце: учитывает правки таблицы и настройки запуска
    show_issues(analysis)
    signature = hashlib.sha256(b"".join(p.encode() + d for p, d in sorted(files.items()))).hexdigest()[:12]
    requirements = dependency_editor(analysis, key=f"deps-{signature}-{use_local_env}")
    entry, python, args, project_name = run_options(analysis, name, signature)
    options = PackOptions(project_name, entry, python, requirements, args)
    package, error = build(analysis, options)
    with summary:
        show_summary(analysis, options, package, error)
    if package is not None:
        show_preview(package)


main()
