"""Статический разбор Python-кода через ast. Загруженный код никогда не импортируется и не выполняется."""

import ast
import io
import itertools
import json
import re
import shlex
import tokenize
from dataclasses import dataclass, replace

DATA_EXTENSIONS = (
    ".csv", ".tsv", ".txt", ".dat", ".json", ".xlsx", ".xls", ".parquet", ".feather",
    ".npy", ".npz", ".h5", ".hdf5", ".nc", ".mat", ".pkl", ".pickle", ".xml", ".yaml", ".yml",
    ".fits", ".wav", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".sqlite", ".db",
)
# Папки, которые есть только на машине автора: домашние, Colab/Kaggle, кластеры, подключённые диски,
# сетевые папки Windows (\\сервер\папка)
ABSOLUTE_PATH = re.compile(r"^(/(home|Users|root|mnt|media|Volumes|data|tmp|var|opt|srv|content|kaggle|scratch"
                           r"|gpfs|lustre)/|[A-Za-z]:[\\/]|~[\\/]|\\\\[^\\])")
RANDOM_CALLS = {"random", "rand", "randn", "randint", "randperm", "shuffle", "choice", "normal", "uniform",
                "permutation", "sample", "integers", "standard_normal"}
RANDOM_OWNERS = {"random", "rng", "generator", "gen", "torch"}
RANDOM_MODULES = {"random", "numpy.random", "torch"}  # from random import shuffle → shuffle(x)
SEED_CALLS = {"seed", "manual_seed", "default_rng", "RandomState", "set_seed"}
SEEDABLE = {"unseeded_random", "unseeded_split"}  # находки, которые снимает любой вызов seed
SYS_PATH_CALLS = {"append", "insert", "extend"}
IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
CLI_MODULES = {"argparse", "click", "typer", "fire", "optparse", "getopt"}
OUTPUT_CALLS = {"savefig", "to_csv", "to_excel", "to_json", "to_parquet", "to_hdf", "to_pickle",
                "save", "savez", "savetxt", "imwrite", "dump", "write_text", "write_bytes", "imsave"}
PATH_TYPES = {"Path", "PurePath", "PosixPath", "WindowsPath"}
NO_REQUIREMENT = (3, 6)
SYNTAX_MIN_PYTHON = {getattr(ast, name): version for name, version in (
    ("NamedExpr", (3, 8)), ("Match", (3, 10)), ("TryStar", (3, 11)), ("TypeAlias", (3, 12)))
    if hasattr(ast, name)}
# Что бросает ast.parse на коде, который не разобрать: синтаксис, NUL-байт (Python 3.11), глубокая вложенность
SYNTAX_ERRORS = (SyntaxError, ValueError)
COMPLEXITY_ERRORS = (RecursionError, MemoryError)
# Логическая строка длиннее — сгенерированная формула. Если файл целиком не разобрался (лимит рекурсии парсера:
# на Windows и в Python 3.11 он ниже), пропускаем только такие строки, а не весь файл с его импортами.
LONG_STATEMENT_TOKENS = 500
LAYOUT_TOKENS = {tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}
# !pip, %pip, !pip3, !python -m pip, !{sys.executable} -m pip, !uv pip
PIP_MAGIC = re.compile(r"^\s*[!%]\s*(?:\S+\s+-m\s+|uv\s+)?pip3?\s+install\s+(.+)$")
# Конец команды pip: «;», «&&», «||», «|», «&» и перенаправления вывода («> log», «2>&1»)
SHELL_STOP = re.compile(r"[;&|]+|\d*[<>].*")
PIP_VALUE_OPTIONS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
                     "--extra-index-url", "-f", "--find-links", "-t", "--target"}
PIP_REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?([<>=!~][^/:@\s]*)?$")
LOCAL_FILE_SUFFIXES = (".txt", ".whl", ".gz", ".zip", ".cfg", ".toml", ".py")
PYTHON_CELL_MAGICS = {"time", "timeit", "capture", "prun", "debug", "memit"}
# Строка-магия IPython: !команда, %магия, ?справка. «!= x» и «% x» в начале строки — продолжение выражения
MAGIC_ROW = re.compile(r"^(\s*)(?:!(?!=)|%%?(?=[A-Za-z])|\?)")
LOAD_EXT = re.compile(r"^\s*%load_ext\s+([A-Za-z_][\w.]*)\s*$")
RUN_SCRIPT = re.compile(r"^\s*%run\s+(?:-\S+\s+)*([A-Za-z_]\w*(?:/[A-Za-z_]\w*)*)\.py(?:\s|$)")
IPYTHON_EXTENSIONS = {"autoreload", "storemagic"}  # входят в IPython, отдельный пакет не нужен

Context = tuple[str, ...]


@dataclass(frozen=True)
class ImportRef:
    module: str   # полное имя через точку; "" для «from . import x»
    line: int
    kind: str     # static | relative | optional | conditional | dynamic
    level: int = 0

    @property
    def top(self) -> str:
        return self.module.split(".", 1)[0]


@dataclass(frozen=True)
class Finding:
    code: str     # см. FINDING_ISSUES в analysis.py
    line: int
    detail: str


@dataclass(frozen=True)
class FileScan:
    path: str
    imports: tuple[ImportRef, ...]
    findings: tuple[Finding, ...]
    data_refs: tuple[tuple[str, int], ...]
    method_calls: frozenset[str]
    min_python: tuple[int, int]
    has_main_guard: bool
    pip_hints: tuple[str, ...] = ()
    cell_lines: tuple[tuple[int, int], ...] = ()  # ноутбук: строка склеенного кода → (ячейка, строка в ней)

    def where(self, line: int) -> str:
        """Место для отчёта: «a.py:12», у ноутбука — «exp.ipynb, ячейка 3, стр. 2»."""
        if not line:
            return self.path
        if line <= len(self.cell_lines):
            cell, row = self.cell_lines[line - 1]
            return f"{self.path}, ячейка {cell}, стр. {row}"
        return f"{self.path}:{line}"


def _dotted(node: ast.AST) -> str:
    """«np.random.rand» для цепочки атрибутов; без рекурсии — цепочки бывают очень длинными."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(_dotted(t).rsplit(".", 1)[-1] in IMPORT_ERRORS for t in types)


def _keyword(node: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in node.keywords if k.arg == name), None)


def _first_arg_is(node: ast.Call, value: str) -> bool:
    return bool(node.args) and isinstance(node.args[0], ast.Constant) and node.args[0].value == value


def _unseeded_split(node: ast.Call) -> bool:
    """train_test_split перемешивает данные, если не передать random_state или shuffle=False."""
    shuffle = _keyword(node, "shuffle")
    no_shuffle = isinstance(shuffle, ast.Constant) and shuffle.value is False
    return _keyword(node, "random_state") is None and not no_shuffle


def _is_home(parts: list[str], node: ast.Call) -> bool:
    """Path.home() и os.path.expanduser("~") — домашняя папка автора, как и «~/…»."""
    if parts[-1] == "expanduser":
        return _first_arg_is(node, "~")
    return parts[-1] == "home" and "Path" in parts[:-1]


def _opens_for_write(node: ast.Call) -> bool:
    modes = [*node.args[1:2], *(k.value for k in node.keywords if k.arg == "mode")]
    return any(isinstance(m, ast.Constant) and set(str(m.value)) & set("wax") for m in modes)


def _is_main_guard(test: ast.AST) -> bool:
    return (
        isinstance(test, ast.Compare)
        and _dotted(test.left) == "__name__"
        and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in test.comparators)
    )


def _is_data_name(value: str) -> bool:
    """Похоже на локальный файл с данными. «.csv» само по себе — расширение (f.endswith('.csv')),
    а «https://…/d.csv» — адрес в интернете, их наличие в загрузке не проверить."""
    bare_extension = value.startswith(".") and "/" not in value
    return (value.lower().endswith(DATA_EXTENSIONS) and " " not in value.strip()
            and not bare_extension and "://" not in value)


def _output_names(node: ast.Call) -> set[str]:
    """Строки в вызове записи — имена выходных файлов, включая Path("x") перед .write_text()."""
    roots = [*node.args, *(k.value for k in node.keywords)]
    receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
    if isinstance(receiver, ast.Call) and _dotted(receiver.func).rsplit(".", 1)[-1] in PATH_TYPES:
        roots.append(receiver)
    return {n.value for root in roots for n in ast.walk(root)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _kind(context: Context) -> str:
    if "optional" in context:
        return "optional"
    return "conditional" if "if" in context else "static"


def _children(node: ast.AST, context: Context) -> list[tuple[ast.AST, Context]]:
    return [(child, context) for child in ast.iter_child_nodes(node)]


class _Visitor:
    """Собирает импорты, находки и пути к данным.

    Дерево обходится стеком, а не рекурсией: формула из тысяч слагаемых (код от sympy)
    иначе упирается в лимит рекурсии Python.
    """

    def __init__(self) -> None:
        self.imports: list[ImportRef] = []
        self.findings: list[Finding] = []
        self.data_refs: list[tuple[str, int]] = []
        self.method_calls: set[str] = set()
        self.has_main_guard = False
        self.first_lines: dict[str, int] = {}  # код находки → первая строка, где она встретилась
        self.random_names: set[str] = set()     # функции, импортированные из random/numpy.random/torch
        self.seeded = False
        self.cli_line = 0
        self.outputs: set[str] = set()

    def run(self, tree: ast.AST) -> None:
        stack: list[tuple[ast.AST, Context]] = [(tree, ())]
        while stack:
            node, context = stack.pop()
            handler = getattr(self, f"visit_{type(node).__name__}", _children)
            stack.extend(reversed(handler(node, context)))

    def visit_Import(self, node: ast.Import, context: Context) -> list:
        self.imports.extend(ImportRef(alias.name, node.lineno, _kind(context)) for alias in node.names)
        return []

    def visit_ImportFrom(self, node: ast.ImportFrom, context: Context) -> list:
        kind = "relative" if node.level else _kind(context)
        self.imports.append(ImportRef(node.module or "", node.lineno, kind, node.level))
        if node.module in RANDOM_MODULES and not node.level:
            self.random_names |= {a.asname or a.name for a in node.names if a.name in RANDOM_CALLS}
        return []

    def visit_Try(self, node: ast.Try, context: Context) -> list:
        guarded = any(_catches_import_error(h) for h in node.handlers)
        inner = (*context, "optional" if guarded else "try")
        return [*((child, inner) for child in (*node.body, *node.handlers)),
                *((child, context) for child in (*node.orelse, *node.finalbody))]

    visit_TryStar = visit_Try

    def visit_If(self, node: ast.If, context: Context) -> list:
        if _is_main_guard(node.test):
            self.has_main_guard = True
            return _children(node, context)
        inner = (*context, "if")
        return [(node.test, context), *((child, inner) for child in (*node.body, *node.orelse))]

    def visit_Call(self, node: ast.Call, context: Context) -> list:
        parts = _dotted(node.func).split(".")
        last, owners = parts[-1], {p.lower() for p in parts[:-1]}
        if isinstance(node.func, ast.Attribute):
            self.method_calls.add(last)
        if last == "import_module" or parts == ["__import__"]:
            self._dynamic_import(node)
        if parts in (["exec"], ["eval"]):
            self._exec(node, parts[0])
        if (last in RANDOM_CALLS and owners & RANDOM_OWNERS) or (len(parts) == 1 and last in self.random_names):
            self.first_lines.setdefault("unseeded_random", node.lineno)
        if last == "train_test_split" and _unseeded_split(node):
            self.first_lines.setdefault("unseeded_split", node.lineno)
        if last in SEED_CALLS and (node.args or node.keywords):
            self.seeded = True
        if last in SYS_PATH_CALLS and parts[:-1] == ["sys", "path"]:
            self.first_lines.setdefault("sys_path", node.lineno)
        if _is_home(parts, node):
            self.findings.append(Finding("absolute_path", node.lineno, ast.unparse(node)))
        if last in OUTPUT_CALLS or (parts == ["open"] and _opens_for_write(node)):
            self.outputs.update(_output_names(node))
        return _children(node, context)

    def _dynamic_import(self, node: ast.Call) -> None:
        arg = node.args[0] if node.args else _keyword(node, "name")
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            self.imports.append(ImportRef(arg.value, node.lineno, "dynamic"))
            self.findings.append(Finding("dynamic_import", node.lineno, arg.value))
        else:
            source = ast.unparse(arg) if arg is not None else ""
            self.findings.append(Finding("dynamic_unresolved", node.lineno, source))

    def _exec(self, node: ast.Call, name: str) -> None:
        """Строка-литерал в exec/eval разбирается (не выполняется) ради импортов; строка, собранная
        при запуске, статически не видна — об этом честное предупреждение."""
        arg = node.args[0] if node.args else None
        if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
            if name == "exec" and arg is not None:
                self.findings.append(Finding("exec_unresolved", node.lineno, ast.unparse(arg)))
            return
        inner = _Visitor()
        try:
            inner.run(ast.parse(arg.value))
        except (*SYNTAX_ERRORS, *COMPLEXITY_ERRORS):
            return
        for ref in inner.imports:
            if not ref.level:
                self.imports.append(ImportRef(ref.module, node.lineno, "dynamic"))
                self.findings.append(Finding("exec_import", node.lineno, ref.module))

    def visit_Attribute(self, node: ast.Attribute, context: Context) -> list:
        if node.attr == "argv" and _dotted(node) == "sys.argv":
            self.cli_line = self.cli_line or node.lineno
        return _children(node, context)

    def visit_JoinedStr(self, node: ast.JoinedStr, context: Context) -> list:
        """Части f-строки — не имена файлов, но абсолютный путь в её начале виден сразу."""
        head = node.values[0] if node.values else None
        if isinstance(head, ast.Constant) and ABSOLUTE_PATH.match(str(head.value)):
            self.findings.append(Finding("absolute_path", node.lineno, ast.unparse(node)))
        return [(part, context) for part in node.values if not isinstance(part, ast.Constant)]

    def visit_Constant(self, node: ast.Constant, context: Context) -> list:
        value = node.value
        if isinstance(value, str) and "\n" not in value and 2 < len(value) < 260:
            if ABSOLUTE_PATH.match(value):
                self.findings.append(Finding("absolute_path", node.lineno, value))
            elif _is_data_name(value):
                self.data_refs.append((value, node.lineno))
        return []


def _min_python(tree: ast.AST) -> tuple[int, int]:
    found = [SYNTAX_MIN_PYTHON[type(n)] for n in ast.walk(tree) if type(n) in SYNTAX_MIN_PYTHON]
    return max(found, default=NO_REQUIREMENT)


def _unreadable(path: str, finding: Finding, pip_hints: tuple[str, ...] = (),
                cell_lines: tuple[tuple[int, int], ...] = ()) -> FileScan:
    return FileScan(path, (), (finding,), (), frozenset(), NO_REQUIREMENT, False, pip_hints, cell_lines)


def _blank_long_statements(text: str) -> tuple[str, list[int]]:
    """Логические строки длиннее LONG_STATEMENT_TOKENS → `pass` (заголовок блока → `if 0:`); номера строк те же."""
    lines, blanked, statement = text.splitlines(keepends=True), [], []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type != tokenize.NEWLINE:
                statement += [] if token.type in LAYOUT_TOKENS else [token]
                continue
            if len(statement) > LONG_STATEMENT_TOKENS:
                (first, column), last = statement[0].start, statement[-1].end[0]
                stub = "if 0:" if statement[-1].string == ":" else "pass"
                lines[first - 1:last] = [lines[first - 1][:column] + stub + "\n"] + ["\n"] * (last - first)
                blanked.append(first)
            statement = []
    except (tokenize.TokenError, SyntaxError):
        return text, []
    return "".join(lines), blanked


def _parse(path: str, text: str) -> tuple[ast.AST, list[Finding]]:
    try:
        return ast.parse(text, filename=path), []
    except COMPLEXITY_ERRORS:
        reduced, blanked = _blank_long_statements(text)
        if not blanked:
            raise
        return ast.parse(reduced, filename=path), [Finding("long_statement", line, "") for line in blanked]


def scan_source(path: str, text: str, pip_hints: tuple[str, ...] = (),
                cell_lines: tuple[tuple[int, int], ...] = ()) -> FileScan:
    try:
        tree, skipped = _parse(path, text)
    except COMPLEXITY_ERRORS:
        finding = Finding("too_complex", 0, "очень глубокая вложенность выражений")
        return _unreadable(path, finding, pip_hints, cell_lines)
    except SYNTAX_ERRORS as exc:
        finding = Finding("syntax_error", getattr(exc, "lineno", None) or 0, getattr(exc, "msg", None) or str(exc))
        return _unreadable(path, finding, pip_hints, cell_lines)
    visitor = _Visitor()
    visitor.run(tree)
    findings = skipped + visitor.findings + [Finding(code, line, "") for code, line in visitor.first_lines.items()
                                   if not (visitor.seeded and code in SEEDABLE)]
    cli_import = next((i for i in visitor.imports if i.top in CLI_MODULES), None)
    if visitor.cli_line or cli_import:
        findings.append(Finding("cli_args", visitor.cli_line or cli_import.line, ""))
    return FileScan(
        path=path,
        imports=tuple(visitor.imports),
        findings=tuple(findings),
        data_refs=tuple(r for r in visitor.data_refs if r[0] not in visitor.outputs),
        method_calls=frozenset(visitor.method_calls),
        min_python=_min_python(tree),
        has_main_guard=visitor.has_main_guard,
        pip_hints=pip_hints,
        cell_lines=cell_lines,
    )


def _parses(code: str) -> bool:
    try:
        ast.parse(code)
    except (*SYNTAX_ERRORS, *COMPLEXITY_ERRORS):
        return False
    return True


def _notebook_cells(text: str) -> list[tuple[int, str]] | None:
    """(номер ячейки, исходный текст) для код-ячеек; None — файл не похож на ноутбук."""
    try:
        cells = json.loads(text).get("cells", [])
    except (ValueError, AttributeError, RecursionError):
        return None
    if not isinstance(cells, list):
        return None
    found = []
    for number, cell in enumerate(cells, start=1):
        source = cell.get("source", "") if isinstance(cell, dict) and cell.get("cell_type") == "code" else None
        if isinstance(source, list):
            source = "".join(part for part in source if isinstance(part, str))
        if isinstance(source, str):
            found.append((number, source))
    return found


def _pip_requirements(args: str) -> list[str]:
    """Пакеты из «pip install …»: опции и их значения, файлы, ссылки и пути пропускаются,
    а на «&& python train.py», «| tail», «> log» команда pip заканчивается."""
    lexer = shlex.shlex(args, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        tokens = args.split()
    tokens = list(itertools.takewhile(lambda token: not SHELL_STOP.fullmatch(token), tokens))
    return [token for previous, token in zip(["", *tokens], tokens)
            if previous not in PIP_VALUE_OPTIONS and PIP_REQUIREMENT.match(token)
            and not token.lower().endswith(LOCAL_FILE_SUFFIXES)]


def _python_row(row: str) -> str:
    """Строка ячейки как Python. Магия (!ls, %matplotlib) становится pass с тем же отступом, чтобы не ломать
    блоки и номера строк; %load_ext X — import X (расширению нужен пакет), %run x.py — import x (скрипт проекта)."""
    magic = MAGIC_ROW.match(row)
    if not magic:
        return row
    extension, script = LOAD_EXT.match(row), RUN_SCRIPT.match(row)
    if extension and extension.group(1) not in IPYTHON_EXTENSIONS:
        return f"{magic.group(1)}import {extension.group(1)}"
    if script:
        return f"{magic.group(1)}import {script.group(1).replace('/', '.')}"
    return f"{magic.group(1)}pass"


def _cell_code(source: str) -> tuple[list[str], list[str]] | None:
    """Строки ячейки как Python и пакеты из !pip install; None — ячейка не на Python (%%bash, %%html…)."""
    rows = source.splitlines()
    first = rows[0].strip() if rows else ""
    if first.startswith("%%") and first[2:].partition(" ")[0] not in PYTHON_CELL_MAGICS:
        return None
    hints = []
    for row in rows:
        if magic := PIP_MAGIC.match(row):
            hints += _pip_requirements(magic.group(1))
    lines = [_python_row(row) + "\n" for row in rows]
    return lines, hints


def scan_notebook(path: str, text: str) -> FileScan:
    """Код-ячейки .ipynb разбираются по отдельности: ячейка с синтаксисом IPython не прячет импорты
    остальных, а места в отчёте указывают номер ячейки и строку в ней."""
    cells = _notebook_cells(text)
    if cells is None:
        return _unreadable(path, Finding("syntax_error", 0, "некорректный JSON ноутбука"))
    code, cell_lines, hints, findings = [], [], [], []
    for number, source in cells:
        parsed = _cell_code(source)
        if parsed is None:
            continue
        lines, cell_hints = parsed
        hints += cell_hints
        if not _parses("".join(lines)):
            findings.append(Finding("cell_syntax_error", 0, f"ячейка {number}"))
            continue
        code += lines
        cell_lines += [(number, row) for row in range(1, len(lines) + 1)]
    scan = scan_source(path, "".join(code), tuple(hints), tuple(cell_lines))
    if hints:
        findings.append(Finding("notebook_magic", 0, " ".join(hints)))
    return replace(scan, findings=scan.findings + tuple(findings))
