"""CLI: python -m repropack <папка|архив.zip|файл.py> [-o пакет.zip]"""

import argparse
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze
from .intake import IntakeError, read_directory, read_file
from .packer import LEVELS, PackOptions, build_zip, default_requirements


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="repropack", description="Пакет воспроизводимости для Python-проекта")
    parser.add_argument("source", type=Path, help="папка проекта, ZIP-архив или .py-файл")
    parser.add_argument("-o", "--output", type=Path, help="куда сохранить ZIP (по умолчанию <имя>-repro.zip)")
    parser.add_argument("--entry", help="точка входа (по умолчанию — лучший кандидат)")
    parser.add_argument("--python", help="версия Python (по умолчанию — предложенная анализом)")
    parser.add_argument("--args", default="", help="аргументы командной строки для запуска")
    parser.add_argument("--local-env", action="store_true", help="разрешить читать версии из текущей среды")
    parser.add_argument("--version", action="version", version=f"repropack {__version__}")
    args = parser.parse_args(argv)

    try:
        files = read_directory(args.source) if args.source.is_dir() else read_file(args.source)
    except (IntakeError, OSError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    analysis = analyze(files, use_local_env=args.local_env)
    if not analysis.entry_candidates:
        print("Ошибка: не найдено файлов для запуска", file=sys.stderr)
        return 1
    name = args.source.resolve().stem
    options = PackOptions(
        project_name=name, entry_point=args.entry or analysis.entry_candidates[0],
        python_version=args.python or analysis.suggested_python,
        requirements=default_requirements(analysis), run_args=args.args,
    )
    output = args.output or Path(f"{name}-repro.zip")
    try:
        output.write_bytes(build_zip(analysis, options))
    except ValueError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Ошибка: не удалось сохранить пакет в {output}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    for issue in analysis.issues:
        where = f" ({issue.where})" if issue.where else ""
        print(f"[{LEVELS[issue.level]}] {issue.title}{where}")
    counts = {level: sum(i.level == level for i in analysis.issues) for level in LEVELS}
    print(f"\nИтого: {counts['high']} критичных, {counts['medium']} требуют решения, {counts['info']} к сведению")
    print(f"Точка входа: {options.entry_point}; Python {options.python_version} ({analysis.python_reason})")
    print(f"Пакет сохранён: {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
