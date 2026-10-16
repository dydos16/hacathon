"""E2E интерфейса: Streamlit AppTest проходит пользовательский сценарий на всех демо-проектах."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).parent.parent / "app.py")


@pytest.mark.parametrize("demo, critical", [("numpy_pandas_script", "0"), ("local_module_project", "0"),
                                            ("messy_lab_project", "6")])
def test_demo_project_flow_renders_without_errors(demo, critical):
    app = AppTest.from_file(APP, default_timeout=30).run()
    app.radio[0].set_value("Демо-проект").run()
    app.selectbox[0].set_value(demo).run()
    assert not app.exception
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Критичных проблем"] == critical
    assert [s.value for s in app.subheader][-1] == "5. Пакет воспроизводимости"


def test_start_screen_asks_for_upload():
    app = AppTest.from_file(APP, default_timeout=30).run()
    assert not app.exception
    assert "Загрузите файлы" in app.info[0].value
