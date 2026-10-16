"""Экранирование пользовательского текста для Markdown: имя файла или строка из кода не должны стать разметкой."""

import re

MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~&])")
BACKTICK_RUN = re.compile(r"`+")


def escape(text: str) -> str:
    """Для обычного текста: спецсимволы становятся буквами, а не ссылками, картинками и выделением."""
    return MARKDOWN_SPECIAL.sub(r"\\\1", text)


def code(text: str) -> str:
    """Для кода в обратных кавычках: длина ограждения больше самой длинной серии кавычек внутри."""
    longest = max(map(len, BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"
