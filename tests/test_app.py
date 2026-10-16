"""E2E интерфейса: Streamlit AppTest проходит пользовательские сценарии — демо, загрузку файлов и ошибки."""

import io
import json
import zipfile
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).parent.parent / "app.py")
CLEAN_PROJECT = {
    "main.py": b"import numpy\n\nif __name__ == '__main__':\n    print(numpy.zeros(1))\n",
    "requirements.txt": b"numpy==1.26.4\n", "README.md": b"# demo\n", "LICENSE": b"MIT\n",
    "data/sample.csv": b"a\n1\n", "tests/test_main.py": b"def test_ok():\n    assert True\n",
}


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def start() -> AppTest:
    return AppTest.from_file(APP, default_timeout=30).run()


def open_demo(demo: str) -> AppTest:
    app = start()
    app.radio[0].set_value("Демо-проект").run()
    app.selectbox[0].set_value(demo).run()
    assert not app.exception
    return app


def upload(*files: tuple[str, bytes]) -> AppTest:
    app = start()
    app.file_uploader[0].set_value([(name, data, "application/octet-stream") for name, data in files]).run()
    assert not app.exception
    return app


def texts(elements) -> str:
    return " | ".join(e.value for e in elements)


def widget(elements, label: str):
    return next(e for e in elements if e.label == label)


NOTEBOOK = json.dumps({"cells": [{"cell_type": "code", "metadata": {}, "outputs": [], "execution_count": None,
                                  "source": ["import numpy\n"]}],
                       "metadata": {}, "nbformat": 4, "nbformat_minor": 5}).encode()


@pytest.mark.parametrize("demo, critical, verdict", [
    ("numpy_pandas_script", "0", "Почти готово"), ("local_module_project", "0", "Явных препятствий нет"),
    ("messy_lab_project", "5", "Скорее всего, у коллеги не запустится")])
def test_demo_project_flow_renders_without_errors(demo, critical, verdict):
    app = open_demo(demo)
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Критичных проблем"] == critical
    assert verdict in texts([*app.error, *app.warning, *app.success])
    assert [s.value for s in app.subheader][-1] == "5. Пакет воспроизводимости"
    assert app.download_button


def test_start_screen_asks_for_upload():
    app = start()
    assert not app.exception
    assert "Загрузите файлы" in app.info[0].value


def test_start_screen_says_what_to_upload_what_comes_out_and_that_code_is_not_run():
    shown = texts(start().markdown)
    assert "Что загрузить" in shown and "Что получите" in shown
    assert "Код не запускается" in shown and "<REDACTED>" in shown


def test_messy_demo_numbers_fit_in_one_row_of_metrics():
    app = open_demo("messy_lab_project")
    assert {m.label: m.value for m in app.metric} == {
        "Файлов": "7", "Внешних пакетов": "12", "Критичных проблем": "5", "Нужно подтвердить": "4"}
    assert any(e.label.startswith("Стандартная библиотека: 4 · локальные модули: 1") for e in app.expander)


def test_each_issue_shows_where_it_is_and_what_to_do():
    app = open_demo("messy_lab_project")
    assert {"Критично: 5", "Нужно решение: 6", "К сведению: 6"} <= {e.label for e in app.expander}
    shown = texts(app.markdown)
    assert "**Абсолютный путь «/Users/ivan/lab/raw_2024.csv»** · `analysis.py:24`" in shown
    assert "→ такой путь есть только на компьютере автора — замените на относительный" in shown


def test_long_issue_list_scrolls_inside_its_group():
    many_missing = "\n".join(f"open('missing_{i}.csv')" for i in range(12)).encode()
    group = widget(upload(("many.py", many_missing)).expander, "Критично: 12")
    assert group.children[0].proto.height_config.pixel_height > 0
    short = widget(open_demo("messy_lab_project").expander, "Критично: 5")
    assert not short.children[0].proto.height_config.pixel_height


@pytest.mark.parametrize("demo, reason", [
    ("numpy_pandas_script", 'в файле есть `if __name__ == "__main__"`'),
    ("local_module_project", "так обычно называют главный скрипт")])
def test_entry_point_choice_is_explained(demo, reason):
    assert f"Точка входа: {reason}" in texts(open_demo(demo).caption)


def test_entry_point_without_any_signs_is_flagged_as_a_guess():
    app = upload(("alpha.py", b"print(1)\n"), ("beta.py", b"print(2)\n"))
    assert "явных признаков нет" in texts(app.caption)


def test_test_file_chosen_as_entry_point_gets_a_warning():
    app = upload(("run_me.py", b"if __name__ == '__main__':\n    pass\n"),
                 ("test_model.py", b"def test_x():\n    pass\n"))
    assert "похож на тест" not in texts(app.warning)
    widget(app.selectbox, "Точка входа").set_value("test_model.py").run()
    assert "похож на тест или служебный файл" in texts(app.warning)


def test_notebook_entry_point_takes_no_arguments():
    app = upload(("exp.ipynb", NOTEBOOK))
    assert widget(app.text_input, "Аргументы запуска").proto.disabled
    assert "nbconvert" in texts(app.caption)
    assert not widget(upload(("exp.py", b"print(1)\n")).text_input, "Аргументы запуска").proto.disabled


def test_switching_project_does_not_carry_over_run_settings():
    app = open_demo("numpy_pandas_script")
    widget(app.text_input, "Аргументы запуска").set_value("--n 5").run()
    widget(app.selectbox, "Python").set_value("3.12").run()
    app.selectbox[0].set_value("local_module_project").run()
    assert widget(app.text_input, "Аргументы запуска").value == ""
    assert widget(app.selectbox, "Python").value == "3.11"
    assert "--n 5" not in app.tabs[0].markdown[0].value


def test_run_arguments_survive_switching_the_entry_point():
    app = open_demo("messy_lab_project")
    widget(app.text_input, "Аргументы запуска").set_value("--n 5").run()
    widget(app.selectbox, "Точка входа").set_value("lab/filters.py").run()
    assert widget(app.text_input, "Аргументы запуска").value == "--n 5"


def test_archive_name_is_shown_and_cyrillic_project_name_is_explained():
    assert "Имя архива: `numpy-pandas-script-repro.zip`" in texts(open_demo("numpy_pandas_script").caption)
    app = upload(("эксперимент.py", b"print(1)\n"))
    assert app.text_input[1].value == "эксперимент"
    assert "Имя архива: `project-repro.zip` — нелатинские буквы в имя файла не попадают" in texts(app.caption)


def test_requirements_and_report_can_be_downloaded_separately():
    app = open_demo("numpy_pandas_script")
    assert [b.proto.label for b in app.download_button] == ["⬇️ Скачать пакет (ZIP)", "requirements.txt",
                                                            "REPORT.md"]


def test_package_summary_shows_data_and_what_was_hidden():
    shown = texts(open_demo("messy_lab_project").markdown)
    assert "**Данные в пакете:** `config.yaml`" in shown
    assert "**Нет в загрузке:** `results/spectra.xlsx`" in shown
    assert "**Исключены (файлы с секретами):** `.env`" in shown
    assert "**Секреты заменены на `<REDACTED>`:** `analysis.py`" in shown
    assert "Исключены" not in texts(open_demo("numpy_pandas_script").markdown)


def test_messy_project_shows_unconfirmed_packages_and_needs_arguments():
    app = open_demo("messy_lab_project")
    assert "Не подтверждены" in texts(app.warning)
    assert "читает аргументы командной строки" in texts(app.caption)


def test_project_without_external_packages_says_so():
    app = open_demo("local_module_project")
    assert "Внешних зависимостей не найдено" in texts(app.info)


def test_python_choice_is_explained_on_screen():
    app = open_demo("numpy_pandas_script")
    assert "Python 3.11 предложен:" in texts(app.caption)


def test_uploaded_single_file_is_analyzed_and_named_after_it():
    app = upload(("experiment.py", b"import pandas\nprint(pandas.__version__)\n"))
    assert {m.label: m.value for m in app.metric}["Внешних пакетов"] == "1"
    assert app.text_input[1].value == "experiment"
    assert "Почти готово" in texts(app.warning)


def test_clean_uploaded_project_has_no_problems():
    app = upload(("clean.zip", make_zip({f"clean/{p}": data for p, data in CLEAN_PROJECT.items()})))
    assert "Проблем не найдено" in texts(app.success)
    assert "Явных препятствий нет" in texts(app.success)
    assert app.text_input[1].value == "clean"


def test_several_uploaded_files_get_a_generic_name():
    app = upload(("main.py", b"print(1)\n"), ("data.csv", b"a\n1\n"))
    assert app.text_input[1].value == "project"


def test_broken_archive_is_rejected_with_a_message():
    app = upload(("project.zip", b"not a zip"))
    assert "Не удалось принять загрузку" in texts(app.error)
    assert not app.metric


def test_project_with_only_service_files_is_explained():
    app = upload(("__init__.py", b""), ("data.csv", b"a\n1\n"))
    assert "только служебные файлы Python" in texts(app.error)
    assert not app.metric


def test_unclosed_quote_in_arguments_blocks_the_package():
    app = open_demo("numpy_pandas_script")
    app.text_input[0].set_value('--name "unclosed').run()
    assert not app.exception
    assert "Пакет не собран" in texts(app.error)
    assert not app.download_button


def test_preview_shows_every_generated_file_from_the_archive():
    app = open_demo("numpy_pandas_script")
    assert [t.label for t in app.tabs] == ["README.md", "requirements.txt", "REPORT.md", "Dockerfile", "verify.sh",
                                           "verify.ps1", "repro.json", "Состав архива"]
    assert "numpy-pandas-script-repro/project/main.py" in app.tabs[-1].code[0].value
    assert "numpy" in app.tabs[1].code[0].value
    assert "Файлов в архиве" in texts(app.caption)
