"""E2E интерфейса: Streamlit AppTest проходит пользовательские сценарии — демо, загрузку файлов и ошибки."""

import io
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


@pytest.mark.parametrize("demo, critical, verdict", [
    ("numpy_pandas_script", "0", "Почти готово"), ("local_module_project", "0", "Явных препятствий нет"),
    ("messy_lab_project", "6", "Скорее всего, у коллеги не запустится")])
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


def test_project_without_runnable_files_is_explained():
    app = upload(("__init__.py", b""))
    assert "нет файлов .py/.ipynb для запуска" in texts(app.error)


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
