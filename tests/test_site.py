"""Сайт в настоящем браузере: запускается streamlit-сервер, Chromium (Playwright) проходит сценарий пользователя.

Включается REPRO_BROWSER_TESTS=1; нужен `pip install -e ".[e2e]"` и `python -m playwright install chromium`.
"""

import io
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("REPRO_BROWSER_TESTS"),
                                reason="REPRO_BROWSER_TESTS=1 — нужен Playwright с Chromium")
ROOT = Path(__file__).parent.parent
TIMEOUT_MS = 90_000


@pytest.fixture(scope="module")
def site(tmp_path_factory) -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    log_path = tmp_path_factory.mktemp("server") / "streamlit.log"
    with open(log_path, "w", encoding="utf-8") as log:
        server = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", str(ROOT / "app.py"), "--server.headless", "true",
             "--server.address", "127.0.0.1", "--server.port", str(port)],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 90
        while True:
            try:
                if urllib.request.urlopen(f"{url}/_stcore/health", timeout=2).read() == b"ok":
                    break
            except OSError:
                pass
            if server.poll() is not None or time.monotonic() > deadline:
                pytest.fail("streamlit не запустился:\n" + log_path.read_text(encoding="utf-8", errors="replace"))
            time.sleep(0.5)
        yield url
    finally:
        server.terminate()
        server.wait(timeout=30)


@pytest.fixture()
def page(site):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        page.set_default_timeout(TIMEOUT_MS)
        page.goto(site)
        page.get_by_role("heading", name="Проект", exact=True).wait_for()
        yield page
        browser.close()


def assert_no_errors(page) -> None:
    exceptions = page.get_by_test_id("stException")
    assert exceptions.count() == 0, exceptions.first.inner_text()


def choose_demo(page, name: str) -> None:
    """Список демо открывается только после того, как Streamlit дорисовал страницу (последняя вкладка
    «Состав архива» на месте): перерисовка после клика по «Демо-проект» закрывает уже открытый список.

    Клик — в само поле выбора, а не в центр блока с подписью: на CI macOS центр блока приходился мимо поля
    и список не открывался. Если перерисовка всё же закрыла список, он открывается ещё раз."""
    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    page.get_by_text("Демо-проект", exact=True).first.click()
    page.get_by_role("tab", name="Состав архива").wait_for()
    field, option = page.get_by_role("combobox", name="Демо-проект"), page.get_by_role("option", name=re.compile(name))
    for _ in range(3):
        field.click()
        try:
            option.wait_for(timeout=10_000)
            break
        except PlaywrightTimeout:
            continue
    option.click()


def download_package(page, root: str) -> list[str]:
    """Скачивает пакет; пока Streamlit пересчитывает страницу, кнопка может отдавать прошлый проект — ждём нужный."""
    deadline = time.monotonic() + TIMEOUT_MS / 1000
    while True:
        with page.expect_download() as download:
            page.get_by_role("button", name=re.compile("Скачать пакет")).click()
        names = zipfile.ZipFile(io.BytesIO(Path(download.value.path()).read_bytes())).namelist()
        if names[0].startswith(f"{root}-repro/") or time.monotonic() > deadline:
            assert names[0].startswith(f"{root}-repro/"), names[:3]
            return names
        time.sleep(1)


def test_demo_project_is_analyzed_and_package_downloads(page):
    choose_demo(page, "messy_lab_project")
    page.get_by_role("button", name=re.compile("Скачать пакет")).wait_for()
    assert_no_errors(page)
    names = download_package(page, "messy-lab-project")
    assert any(n.endswith("/verify.sh") for n in names) and any(n.endswith("/verify.ps1") for n in names)
    assert not any(n.endswith("/project/.env") for n in names)


def test_uploaded_zip_is_analyzed_in_browser(page, tmp_path: Path):
    archive = tmp_path / "local_module_project.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for file in (ROOT / "examples" / "local_module_project").rglob("*.py"):
            zf.write(file, file.relative_to(ROOT / "examples").as_posix())
    page.locator("input[type=file]").set_input_files(str(archive))
    page.get_by_role("button", name=re.compile("Скачать пакет")).wait_for()
    assert_no_errors(page)
    names = download_package(page, "local-module-project")
    assert any(n.endswith("/project/main.py") for n in names) and any(n.endswith("/README.md") for n in names)
