# Что поправлено (changelog)

Ниже — список изменений относительно предыдущей версии проекта. По файлам и по сути.

---

## 1. `repropack/intake.py` — безопасность приёма ZIP

- **Compression ratio.** Добавлен лимит `MAX_COMPRESSION_RATIO = 200`: если `file_size / compress_size` превышает порог — `IntakeError("Подозрительная степень сжатия… (возможна zip-бомба)")`. Раньше проверялся только суммарный распакованный размер, из-за чего архив с одним сильно сжатым файлом проходил.
- **Per-file лимит.** Добавлен `MAX_FILE_BYTES = 5 МБ`. Проверяется и для записей внутри ZIP, и для одиночных загруженных файлов в `read_upload`. Раньше одиночный `.py` на 500 МБ принимался.
- **Symlink в ZIP.** Записи с `external_attr >> 16 & 0o170000 == 0o120000` отклоняются с сообщением «Символическая ссылка в архиве».
- **Нулевые байты и переводы строк в имени файла.** В `_safe_path` добавлена проверка `if any(c in raw for c in "\x00\r\n")` **до** любых манипуляций с `PurePosixPath`. Раньше `main.py\x00.txt` мог обрезаться до `main.py` на уровне `open()`.

## 2. `repropack/classify.py` — приоритет объявленного над справочником

- **`_resolve_package` переписана.** Теперь порядок такой:
  1. Явное объявление в проекте (`requirements.txt`, `pyproject.toml`, `environment.yml`, `!pip install`) **побеждает справочник**.
  2. Справочник `known` — с учётом альтернатив (см. ниже).
  3. `ambiguous`.
  4. Объявленные, но не попавшие в `known`.
  5. Локальная среда (если разрешено).
  6. «Догадка».
- **Альтернативы из справочника.** Если у модуля есть `"<module>#alternatives"`, и один из вариантов объявлен в проекте — берётся он, статус «объявлено в проекте», `needs_confirmation=False`. Если ни один не объявлен — берётся значение по умолчанию, но выставляется `needs_confirmation=True` и в `candidates` попадают все альтернативы, чтобы пользователь выбрал.
- **Раньше** `opencv-python-headless` в `requirements.txt` игнорировался: `cv2` жёстко маппился на `opencv-python` из справочника.

## 3. `repropack/data/module_to_package.json` — альтернативы

Добавлены ключи:

- `cv2#alternatives`: `opencv-python`, `opencv-python-headless`, `opencv-contrib-python`
- `PIL#alternatives`: `Pillow`, `Pillow-SIMD`
- `torch#alternatives`: `torch`, `torch-cpu`, `torch-cuda`
- `faiss#alternatives`: `faiss-cpu`, `faiss-gpu`
- `umap#alternatives`: `umap-learn`
- `Crypto#alternatives`: `pycryptodome`, `pycrypto`

Формат сохранён обратно-совместимым: `known` остаётся `dict[str, str]`, `#alternatives` — просто дополнительный ключ, который старый код игнорирует, а новый читает. Схему загрузки менять не пришлось.

## 4. `repropack/packer.py` — детерминированный ZIP

- В `PackOptions` добавлены поля:
  - `created: str = ""` — фиксированное время создания пакета; одно значение идёт и в `render_package`, и в `build_zip`.
  - `zip_date: tuple[int,int,int,int,int,int] = (1980, 1, 1, 0, 0, 0)` — дата внутри ZIP-записей.
- `render_package` больше не вызывает `datetime.now()` безусловно: сначала берёт `created` из `options`, потом из аргумента, и только потом — текущее время.
- `build_zip` использует `options.zip_date` вместо `datetime.now().timetuple()[:6]`. Раньше два запуска на одном входе давали разные SHA-256.
- `build_zip` прокидывает то же `created` в `render_package`, чтобы содержимое `README.md`/`REPORT.md` и ZIP-записей было согласовано.

## 5. `app.py` — стабильный `created` на сессию

- В `download_section` добавлено:
  ```python
  if "pack_created" not in st.session_state:
      st.session_state.pack_created = datetime.now(timezone.utc).isoformat(timespec="seconds")
  options = replace(options, created=st.session_state.pack_created)
  ```
  Превью и содержимое ZIP теперь совпадают, а повторное нажатие «Скачать» даёт тот же файл.

## 6. `repropack/analysis.py` — честная обработка «удалённых» модулей

- `_dependency_issues` принимает `python_version`.
- Если модуль из `REMOVED_STDLIB` удалён в версии **новее** предложенной, предупреждение понижается до `info`: «модуль удалён из Python X.Y, но на предложенном Python Z.W ещё доступен». Раньше `cgi` при предложенном Python 3.11 давал `high`-предупреждение, хотя на 3.11 он есть.
- `analyze` передаёт вычисленный `python` в `_dependency_issues`.
- Добавлена `_mask_path`: для finding'а `absolute_path` в `detail` теперь `/Users/***/raw.csv` вместо `/Users/ivan/raw.csv` — структура директорий автора не утекает в `repro.json` и `REPORT.md`.

## 7. `repropack/scanner.py` — `np.random.default_rng().normal(...)`

- `_dotted` теперь умеет `ast.Call`: для `np.random.default_rng().normal` возвращает `"np.random.default_rng().normal"`.
- В `visit_Call` разбор `parts`/`owners` переписан с учётом `()` и добавлено условие `any("random" in o for o in owners)`. Раньше `np.random.default_rng().normal(size=3)` без seed не ловился: `_dotted` возвращал пустую строку для `Call`.

## 8. `repropack/secrets.py` — мелочи

- В `SECRET_FILE_NAMES` добавлен `.envrc`.
- `PRIVATE_KEY_BLOCK` заменён на нежадный вариант, останавливающийся либо на `-----END … PRIVATE KEY-----`, либо на первой пустой строке после `BEGIN`. Раньше при отсутствии `END` регулярка съедала весь остаток файла до `\Z`, включая полезный код после ключа.

## 9. Шаблоны — предупреждения и версия Python

- **`README.md.j2`**: первым блоком после заголовка добавлено предупреждение «`verify.sh` запускает код автора проекта. Запускайте только если доверяете источнику».
- **`verify.sh.j2`**: добавлены `set -eu`, проверка наличия интерпретатора, проверка соответствия `python_version` (с предупреждением, а не падением) и пояснение при незафиксированных версиях: «установятся последние совместимые версии; точные — в `requirements.lock.txt`».
- **`Dockerfile.j2`**: комментарий о том, что базовый образ выбран по предложенной версии Python и его можно заменить, если для этой версии нет `python:<version>-slim`.

## 10. Документация

- **`README.md`** (корневой) — переписан:
  - раздел «Безопасность» больше не утверждает «секреты не покидают машину», а говорит «**найденные** секреты не покидают машину» и добавляет явный дисклеймер про эвристику и `verify.sh`;
  - добавлен раздел «Детерминированность пакета»;
  - таблица MVP дополнена пунктами про symlink, compression ratio, per-file лимит и альтернативы в справочнике;
  - убран непроверяемый процент покрытия.
- **`LIMITATIONS.md`** — добавлены разделы:
  - «Безопасность»: `verify.sh` запускает код автора; эвристика секретов; `.env.example` не исключается;
  - «Детерминированность»: одинаковый вход + одинаковый `created` → одинаковый SHA-256; файлы с найденными секретами редактуруются, остальные копируются байт в байт.

## 11. Тесты

Добавлены/обновлены:

- `test_packer.py::test_zip_is_deterministic` — две сборки на одном входе дают одинаковый SHA-256.
- `test_intake.py::test_zip_bomb_by_compression_ratio_is_rejected` — 2 МБ нулей, сжатые в килобайты, отклоняются.
- `test_intake.py::test_zip_with_symlink_is_rejected` — запись с `S_IFLNK` отклоняется.
- `test_intake.py::test_oversized_single_file_is_rejected` — per-file лимит работает.
- `test_intake.py::test_control_chars_in_name_are_rejected` — `\x00`, `\r`, `\n` в имени отклоняются.
- `test_classify.py::test_declared_alternative_overrides_mapping_default` — `opencv-python-headless` в `requirements.txt` побеждает справочник.
- `test_classify.py::test_removed_module_is_info_when_python_still_has_it` — `cgi` на Python 3.11 даёт `info`, а не `high`.
- `test_scanner.py::test_default_rng_without_seed_is_flagged` и `test_default_rng_with_seed_is_not_flagged` — `np.random.default_rng().normal(...)` ловится и не ловится при seed.

## 12. `pyproject.toml` / прочее

- Без изменений по зависимостям; `requires-python = ">=3.11"` сохранён.
- `ast.unparse` используется только на 3.11+, что согласовано с `requires-python`.

---

## Что осталось как было (осознанно)

- `verify.ps1` не покрыт автотестами — CI на Windows нет, это отмечено в `LIMITATIONS.md`.
- `setup.py` не разбирается — только декларативные `pyproject.toml`/`requirements.txt`/`environment.yml`.
- Динамические импорты с вычисляемым именем не разрешаются — только предупреждение.
- Справочник «модуль → пакет» не берётся из PyPI-метаданных, собран вручную.
