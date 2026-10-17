"""Streamlit-интерфейс: проект → итог со скачиванием → проблемы → зависимости → запуск → содержимое пакета."""

import base64
import hashlib
import io
import os
import zipfile
from pathlib import Path, PurePosixPath

import pandas as pd
import streamlit as st

from repropack.analysis import ENTRY_NAMES, Analysis, Issue, analyze, is_auxiliary
from repropack.classify import LOCAL_ENV, Dependency
from repropack.intake import IntakeError, check_upload, read_directory, read_upload
from repropack.markdown import code, escape
from repropack.packer import (CATEGORIES, PACKAGE_NAME, VERSION_SPEC, PackOptions, Requirement, build_zip,
                              default_requirements, packaged_dependencies, slugify)
from repropack.scanner import FileScan

EXAMPLES = {
    "numpy_pandas_script": "Скрипт с numpy/pandas и CSV-данными",
    "local_module_project": "Скрипт с локальным модулем (без внешних пакетов)",
    "messy_lab_project": "«Сырой» проект: секреты, динамические импорты, пропавшие данные",
}
EXAMPLES_DIR = Path(__file__).parent / "examples"
UI_DIR = Path(__file__).parent / "ui"  # оформление: style.css и иллюстрация первого экрана — правятся без кода
SOURCES = ["Файлы или ZIP", "Папка проекта", "Демо-проект"]
PYTHON_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13"]
# Уровень → заголовок группы и цвет текста (цвет вместо значков: красный — только для критичного)
LEVEL_LABELS = {"high": ("Критично", "red"), "medium": ("Нужно решение", "orange"), "info": ("К сведению", "gray")}
ISSUES_BEFORE_SCROLL = 8
ISSUE_LIST_HEIGHT = 420  # px: длинный список прокручивается внутри своей группы
START_SCREEN = (
    ("Что загрузить", "Папку проекта целиком, ZIP или отдельные файлы `.py` и `.ipynb` (до 150 МБ каждый). "
                      "Данные и `requirements.txt` можно приложить рядом."),
    ("Что получите", "ZIP: `requirements.txt` с пояснением к каждой строке, README с командами, Dockerfile, "
                     "`verify.sh` / `verify.ps1` и отчёт о том, что определить не удалось."),
    ("Код не запускается", "Только статический разбор (`ast`) в памяти, на диск ничего не сохраняется. "
                           "Файлы с секретами исключаются, ключи в коде заменяются на `<REDACTED>`."),
)
HERO_CHIPS = ("код не запускается", "verify.sh · verify.ps1", "Windows · Linux · macOS")
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
ANALYSIS_STATE = "analysis"  # ключ st.session_state: разбор текущей загрузки

st.set_page_config(page_title="repro-packer", layout="wide")


def signature(files: dict[str, bytes]) -> str:
    """Отпечаток загрузки; длина перед содержимым — «a.py»+«x» и «a.p»+«yx» не совпадут."""
    digest = hashlib.sha256()
    for path, data in sorted(files.items()):
        digest.update(f"{path}\0{len(data)}\0".encode())
        digest.update(data)
    return digest.hexdigest()[:12]


def session_analysis(files: dict[str, bytes], use_local_env: bool, key: str) -> Analysis:
    """Разбор хранится в сессии посетителя, а не в общем кэше st.cache_data: байты загрузки (вместе
    с исключённым .env и ключами в коде) живут не дольше самой загрузки и другим сессиям не достаются.
    Одна запись на сессию: новая загрузка вытесняет прежнюю, а убранная или отклонённая — удаляет её."""
    cached = st.session_state.get(ANALYSIS_STATE)
    if cached is None or cached[0] != (key, use_local_env):
        with st.spinner("Статический разбор кода…"):
            cached = st.session_state[ANALYSIS_STATE] = (key, use_local_env), analyze(files, use_local_env)
    return cached[1]


def choose_source() -> tuple[dict[str, bytes], str] | None:
    """Файлы или ZIP, папка целиком (подпапки сохраняются) или демо-проект → (файлы, имя проекта)."""
    mode = st.radio("Источник", SOURCES, horizontal=True, label_visibility="collapsed")
    if mode == "Демо-проект":
        name = st.selectbox("Демо-проект", EXAMPLES, format_func=lambda k: f"{k} — {EXAMPLES[k]}")
        return read_directory(EXAMPLES_DIR / name), name
    folder = mode == "Папка проекта"
    uploads = st.file_uploader("Папка проекта: подпапки сохранятся, .git и .venv пропускаются" if folder
                               else "Файлы проекта: .py, .ipynb, ZIP-архив, данные и requirements",
                               accept_multiple_files="directory" if folder else True)
    if not uploads:
        return None
    # Лимиты — по UploadedFile.size, до чтения: слишком большая загрузка не копируется в память целиком
    check_upload([(u.name, u.size) for u in uploads], keep_paths=folder)
    files = read_upload([(u.name, u.getvalue()) for u in uploads], keep_paths=folder)
    if folder:  # имя загруженного файла — путь внутри папки, начиная с имени самой папки
        return files, PurePosixPath(uploads[0].name).parts[0]
    return files, Path(uploads[0].name).stem if len(uploads) == 1 else "project"


def apply_style() -> None:
    """Стили и анимации сайта — в ui/style.css; тексты и порядок блоков задаёт только этот файл."""
    st.html(f"<style>{(UI_DIR / 'style.css').read_text(encoding='utf-8')}</style>")


def show_hero() -> None:
    """Первый экран: название и суть слева, анимированная схема «файлы → разбор → пакет» справа."""
    with st.container(key="hero"):
        text, art = st.columns([3, 2], vertical_alignment="center")
        with text:
            st.html('<p class="rp-eyebrow">Обнинский хакатон 2026 · кейс 03</p>')
            st.title("repro-packer")
            st.markdown("Собирает из научного Python-проекта пакет, который коллега повторит у себя: "
                        "`requirements.txt`, README, Dockerfile и скрипт проверки. Код проекта не запускается — "
                        "только читается.")
            st.html('<ul class="rp-chips">' + "".join(f"<li>{chip}</li>" for chip in HERO_CHIPS) + "</ul>")
        # Картинкой, а не встроенным SVG: st.html вырезает <svg>, а анимация внутри <img> с SVG работает
        art.html(f'<img class="rp-art" alt="" src="data:image/svg+xml;base64,'
                 f'{base64.b64encode((UI_DIR / "hero.svg").read_bytes()).decode()}">')


def show_start_screen() -> None:
    with st.container(key="start"):
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
    return "  \n".join(f"**{label}:** {', '.join(code(p) for p in items)}" for label, items in facts if items)


def local_env_summary(analysis: Analysis) -> str:
    """С галочкой «версии из среды»: где и какие версии прочитаны — видно без открытия REPORT.md."""
    if not analysis.environment:
        return ""
    where = ", ".join(f"{name} {value}" for name, value in analysis.environment)
    read = [f"`{d.package}{d.version}`" for d in analysis.dependencies if d.version_source == LOCAL_ENV]
    return f"**Версии из локальной среды ({where}):** {', '.join(read) or 'пакеты проекта здесь не установлены'}"


def show_summary(analysis: Analysis, options: PackOptions, package: bytes | None, error: str) -> None:
    """Итог наверху страницы: вердикт, числа и скачивание — без прокрутки к концу."""
    show_verdict(analysis)
    show_metrics(analysis, options.requirements)
    if package is None:
        st.error(f"Пакет не собран: {escape(error)}")
        return
    names, generated = unpack(package)
    with st.container(horizontal=True):
        st.download_button("Скачать пакет (ZIP)", package, file_name=f"{names[0].split('/', 1)[0]}.zip",
                           mime="application/zip", type="primary")
        st.download_button("requirements.txt", generated["requirements.txt"], file_name="requirements.txt",
                           mime="text/plain")
        st.download_button("REPORT.md", generated["REPORT.md"], file_name="REPORT.md", mime="text/markdown")
    if summary := "  \n".join(filter(None, (package_summary(analysis), local_env_summary(analysis)))):
        st.markdown(summary)
    notes = ["У коллеги: распакуйте архив и запустите `sh verify.sh` (Windows: `verify.ps1`). Итог — в конце "
             "`verify_log.txt`, точные версии — в `requirements.lock.txt`."]
    if unconfirmed := [r.package for r in options.requirements if not r.confirmed]:
        notes.insert(0, f"Не подтверждены: {', '.join(map(escape, unconfirmed))} — попадут в requirements.txt с пометкой.")
    st.caption("  \n".join(notes))


def issue_markdown(issue: Issue) -> str:
    """Что случилось и где — первой строкой, что сделать — второй."""
    where = f" · {code(issue.where)}" if issue.where else ""
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
                    + ("" if project_name.isascii() else " — нелатинские буквы в имя файла не попадают, хэш в конце отличает его от других проектов"))
    if is_auxiliary(entry):  # то же правило, по которому такие файлы стоят в конце списка
        st.warning(f"{code(entry)} похож на тест или служебный файл — эксперимент обычно запускают другим скриптом.")
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
    apply_style()
    show_hero()
    st.subheader("Проект")
    try:
        source = choose_source()
    except IntakeError as exc:
        st.session_state.pop(ANALYSIS_STATE, None)
        st.error(f"Не удалось принять загрузку: {escape(str(exc))}")
        return
    # На общем сервере (REPRO_PUBLIC=1) версии «из среды» — это пакеты и ОС сервера, их не показываем посетителям
    use_local_env = not os.environ.get("REPRO_PUBLIC") and st.checkbox(
        "Читать версии пакетов из среды, где запущен repro-packer",
        help="Только при локальном запуске: версии берутся из importlib.metadata этой машины. "
             "Без согласия версии не читаются.")
    if source is None:
        st.session_state.pop(ANALYSIS_STATE, None)
        show_start_screen()
        return
    files, name = source
    key = signature(files)
    analysis = session_analysis(files, use_local_env, key)
    if not analysis.entry_candidates:
        st.error("Нечего запускать: в загрузке только служебные файлы Python (`__init__.py`, `__main__.py`…). "
                 "Добавьте скрипт или ноутбук, который проводит эксперимент.")
        return
    summary = st.container(border=True, key="summary")  # заполняется в конце: учитывает правки таблицы
    show_issues(analysis)
    requirements = dependency_editor(analysis, key=f"deps-{key}-{use_local_env}")
    entry, python, args, project_name = run_options(analysis, name, key)
    options = PackOptions(project_name, entry, python, requirements, args)
    package, error = build(analysis, options)
    with summary:
        show_summary(analysis, options, package, error)
    if package is not None:
        show_preview(package)


main()
