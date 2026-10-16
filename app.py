"""Streamlit-интерфейс: загрузка → проверка зависимостей → предупреждения → скачивание пакета."""

import hashlib
import io
import zipfile
from pathlib import Path

import pandas as pd
import streamlit as st

from repropack.analysis import Analysis, analyze
from repropack.intake import IntakeError, read_directory, read_upload
from repropack.packer import (CATEGORIES, PACKAGE_NAME, VERSION_SPEC, PackOptions, Requirement, build_zip,
                              default_requirements, packaged_dependencies, slugify)

EXAMPLES = {
    "numpy_pandas_script": "Скрипт с numpy/pandas и CSV-данными",
    "local_module_project": "Скрипт с локальным модулем (без внешних пакетов)",
    "messy_lab_project": "«Сырой» проект: секреты, динамические импорты, пропавшие данные",
}
EXAMPLES_DIR = Path(__file__).parent / "examples"
PYTHON_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13"]
LEVEL_VIEW = {"high": (st.error, "Критично"), "medium": (st.warning, "Нужно решение"), "info": (st.info, "К сведению")}
EDITABLE = ["Включить", "Пакет PyPI", "Версия", "Подтверждено"]
INFO_COLUMNS = ["Модуль", "Категория", "Откуда", "Варианты", "Комментарий", "Где"]
# Ячейки проверяются тем же regex, что и при сборке: неверное значение не принимается ещё в таблице
EDITOR_COLUMNS = {
    "Включить": st.column_config.CheckboxColumn(default=True),
    "Пакет PyPI": st.column_config.TextColumn(required=True, validate=PACKAGE_NAME.pattern,
                                              help="имя на PyPI, например scikit-learn"),
    "Версия": st.column_config.TextColumn(validate=VERSION_SPEC.pattern, help="например 1.26.4 или >=2.0"),
    "Подтверждено": st.column_config.CheckboxColumn(default=True,
                                                    help="снимите, если не уверены, — в requirements.txt будет пометка"),
}
# Файлы пакета для предпросмотра → язык подсветки ("markdown" — показать как текст)
PREVIEW = {"README.md": "markdown", "requirements.txt": "text", "REPORT.md": "markdown", "Dockerfile": "dockerfile",
           "verify.sh": "bash", "verify.ps1": "powershell", "repro.json": "json"}
PREVIEW_HEIGHT = 480  # px: длинный отчёт прокручивается внутри вкладки, а не растягивает страницу

st.set_page_config(page_title="repro-packer", page_icon="📦", layout="wide")


@st.cache_data(show_spinner="Статический разбор кода…")
def cached_analysis(files: dict[str, bytes], use_local_env: bool) -> Analysis:
    return analyze(files, use_local_env)


def sidebar() -> bool:
    with st.sidebar:
        st.header("Как это работает")
        st.markdown("1. Загрузите `.py`, `.ipynb` или ZIP проекта\n2. Проверьте и подтвердите пакеты\n"
                    "3. Разберите предупреждения\n4. Скачайте пакет и запустите `verify.sh` у коллеги")
        st.success("🔒 Загруженный код **не выполняется**: импорты извлекаются статически (`ast`).")
        st.caption("Секреты не показываются целиком и вырезаются из пакета.")
        return st.checkbox("Читать версии пакетов из среды, где запущен repro-packer",
                           help="Только при локальном запуске: версии берутся из importlib.metadata этой машины. "
                                "Без согласия версии не читаются.")


def choose_source() -> tuple[dict[str, bytes], str] | None:
    mode = st.radio("Источник", ["Загрузить свой проект", "Демо-проект"], horizontal=True,
                    label_visibility="collapsed")
    if mode == "Демо-проект":
        name = st.selectbox("Демо-проект", EXAMPLES, format_func=lambda k: f"{k} — {EXAMPLES[k]}")
        return read_directory(EXAMPLES_DIR / name), name
    uploads = st.file_uploader("Файлы проекта: .py, .ipynb, ZIP-архив, данные и requirements",
                               accept_multiple_files=True)
    if not uploads:
        st.info("Загрузите файлы или выберите демо-проект.")
        return None
    name = Path(uploads[0].name).stem if len(uploads) == 1 else "project"
    return read_upload([(u.name, u.getvalue()) for u in uploads]), name


def show_metrics(analysis: Analysis) -> None:
    deps = analysis.dependencies
    cols = st.columns(5)
    cols[0].metric("Файлов", len(analysis.files))
    cols[1].metric("Внешних пакетов", len(packaged_dependencies(analysis)))
    builtin_local = f"{sum(d.category == 'stdlib' for d in deps)} / {sum(d.category == 'local' for d in deps)}"
    cols[2].metric("Встроенные / локальные", builtin_local,
                   help="Модули стандартной библиотеки / модули самого проекта")
    cols[3].metric("Критичных проблем", sum(i.level == "high" for i in analysis.issues))
    cols[4].metric("Нужно подтвердить", sum(d.needs_confirmation for d in deps))


def show_verdict(analysis: Analysis) -> None:
    """Одна строка-ответ на главный вопрос: можно ли уже отдавать пакет коллеге."""
    high = sum(i.level == "high" for i in analysis.issues)
    medium = sum(i.level == "medium" for i in analysis.issues)
    if high:
        st.error(f"**Скорее всего, у коллеги не запустится.** Критичных проблем: {high} — исправьте их "
                 "по разделу 3 и загрузите проект заново.", icon="🔴")
    elif medium:
        st.warning(f"**Почти готово.** Пунктов, где нужно ваше решение: {medium} — проверьте таблицу "
                   "зависимостей и раздел 3.", icon="🟡")
    else:
        st.success("**Явных препятствий нет.** Скачайте пакет и проверьте его командой `verify.sh` "
                   "на чистой машине.", icon="🟢")


def _cell(row: pd.Series, column: str) -> str:
    value = row.get(column)
    return "" if value is None or pd.isna(value) else str(value).strip()


def _flag(row: pd.Series, column: str) -> bool:
    """Пустая ячейка в строке, добавленной вручную, считается «да»."""
    value = row.get(column)
    return True if value is None or pd.isna(value) else bool(value)


def dependency_editor(analysis: Analysis, key: str) -> tuple[Requirement, ...]:
    st.subheader("2. Зависимости")
    st.caption("Исправьте имя пакета или версию, снимите «Включить» у лишних, отметьте «Подтверждено». "
               "Строки с ⚠ требуют решения человека. Можно добавить строку вручную.")
    rows = pd.DataFrame([{
        "Включить": True, "Пакет PyPI": r.package, "Версия": r.version, "Подтверждено": r.confirmed,
        "Модуль": ("⚠ " if d.needs_confirmation else "") + d.module, "Категория": CATEGORIES[d.category],
        "Откуда": d.status + (f" · версия: {d.version_source}" if d.version_source else ""),
        "Варианты": ", ".join(d.candidates), "Комментарий": r.comment, "Где": ", ".join(d.locations[:3]),
    } for d, r in zip(packaged_dependencies(analysis), default_requirements(analysis))],
        columns=["Модуль", *EDITABLE, *INFO_COLUMNS[1:]])
    if rows.empty:
        st.info("Внешних зависимостей не найдено — requirements.txt будет без пакетов.")
    edited = st.data_editor(rows, key=key, num_rows="dynamic", width="stretch", hide_index=True,
                            disabled=INFO_COLUMNS, column_config=EDITOR_COLUMNS)
    with st.expander("Стандартная библиотека и локальные модули (в requirements не попадают)"):
        st.dataframe(pd.DataFrame([{"Модуль": d.module, "Категория": CATEGORIES[d.category],
                                    "Где": ", ".join(d.locations[:3])}
                                   for d in analysis.dependencies if d.category in ("stdlib", "local")]),
                     width="stretch", hide_index=True)
    return tuple(
        Requirement(_cell(row, "Пакет PyPI"), _cell(row, "Версия"),
                    _cell(row, "Комментарий") if _cell(row, "Модуль") else "добавлено вручную",
                    _flag(row, "Подтверждено"))
        for _, row in edited.iterrows()
        if _flag(row, "Включить") and _cell(row, "Пакет PyPI")
    )


def show_issues(analysis: Analysis) -> None:
    st.subheader("3. Что мешает воспроизвести")
    if not analysis.issues:
        st.success("Проблем не найдено.")
    for level, (render, label) in LEVEL_VIEW.items():
        issues = [i for i in analysis.issues if i.level == level]
        if not issues:
            continue
        with st.expander(f"{label}: {len(issues)}", expanded=level != "info"):
            for issue in issues:
                where = f"  \n`{issue.where}`" if issue.where else ""
                render(f"**{issue.title}** — {issue.detail}{where}")


def run_options(analysis: Analysis, name: str) -> tuple[str, str, str, str]:
    st.subheader("4. Как запускать")
    cols = st.columns([2, 1, 2, 2])
    entry = cols[0].selectbox("Точка входа", analysis.entry_candidates,
                              help="Первым предложен файл с `if __name__ == '__main__'`")
    versions = sorted({*PYTHON_VERSIONS, analysis.suggested_python}, key=lambda v: tuple(map(int, v.split("."))))
    python = cols[1].selectbox("Python", versions, index=versions.index(analysis.suggested_python))
    needs_args = any(f.code == "cli_args" for s in analysis.scans if s.path == entry for f in s.findings)
    args = cols[2].text_input("Аргументы запуска", placeholder="--input data.csv" if needs_args else "")
    project_name = cols[3].text_input("Название проекта", value=name)
    st.caption(f"Python {analysis.suggested_python} предложен: {analysis.python_reason}.")
    if needs_args and not args:
        st.caption("ℹ️ Точка входа читает аргументы командной строки — при необходимости укажите их.")
    return entry, python, args, project_name


def download_section(analysis: Analysis, options: PackOptions) -> None:
    st.subheader("5. Пакет воспроизводимости")
    try:
        package = build_zip(analysis, options)
    except ValueError as exc:
        st.error(f"Пакет не собран: {exc}")
        return
    unconfirmed = [r.package for r in options.requirements if not r.confirmed]
    if unconfirmed:
        st.warning(f"Не подтверждены: {', '.join(unconfirmed)} — попадут в requirements.txt с пометкой.")
    st.download_button("⬇️ Скачать пакет (ZIP)", package, file_name=f"{slugify(options.project_name)}-repro.zip",
                       mime="application/zip", type="primary")
    # Предпросмотр читается из готового архива — показано ровно то, что будет скачано
    archive = zipfile.ZipFile(io.BytesIO(package))
    names = archive.namelist()
    root = names[0].split("/", 1)[0]
    st.caption(f"Файлов в архиве: {len(names)} · {len(package) / 1024:.0f} КБ")
    tabs = st.tabs([*PREVIEW, "Состав архива"])
    for tab, (name, language) in zip(tabs, PREVIEW.items()):
        text = archive.read(f"{root}/{name}").decode("utf-8-sig")
        with tab, st.container(height=PREVIEW_HEIGHT):
            if language == "markdown":
                st.markdown(text)
            else:
                st.code(text, language=language)
    tabs[-1].code("\n".join(names), language="text")
    st.info("**Проверка у коллеги:** распакуйте архив → `sh verify.sh` (Windows: `verify.ps1`) → "
            "в конце `verify_log.txt` будет `РЕЗУЛЬТАТ: OK` или причина ошибки, а точные версии — "
            "в `requirements.lock.txt`.")


def main() -> None:
    use_local_env = sidebar()
    st.title("📦 repro-packer")
    st.markdown("**Повтори мой эксперимент:** превращает научный Python-скрипт в переносимый пакет — "
                "requirements.txt, README с командами, Dockerfile, скрипт проверки и честный отчёт о том, "
                "что определить не удалось.")
    st.subheader("1. Проект")
    try:
        source = choose_source()
    except IntakeError as exc:
        st.error(f"Не удалось принять загрузку: {exc}")
        return
    if source is None:
        return
    files, name = source
    analysis = cached_analysis(files, use_local_env)
    if not analysis.entry_candidates:
        st.error("В проекте нет файлов .py/.ipynb для запуска.")
        return
    show_metrics(analysis)
    show_verdict(analysis)
    signature = hashlib.sha256(b"".join(p.encode() + d for p, d in sorted(files.items()))).hexdigest()[:12]
    requirements = dependency_editor(analysis, key=f"deps-{signature}-{use_local_env}")
    show_issues(analysis)
    entry, python, args, project_name = run_options(analysis, name)
    download_section(analysis, PackOptions(project_name or name, entry, python, requirements, args))


main()
