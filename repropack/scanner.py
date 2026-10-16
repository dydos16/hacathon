"""Статический разбор Python-кода через ast. Загруженный код никогда не импортируется и не выполняется."""

import ast
import json
import re
from dataclasses import dataclass, replace

DATA_EXTENSIONS = (
    ".csv", ".tsv", ".txt", ".dat", ".json", ".xlsx", ".xls", ".parquet", ".feather",
    ".npy", ".npz", ".h5", ".hdf5", ".nc", ".mat", ".pkl", ".pickle", ".xml", ".yaml", ".yml",
    ".fits", ".wav", ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".sqlite", ".db",
)
ABSOLUTE_PATH = re.compile(r"^(/(home|Users|mnt|media|data|tmp|var|opt|srv)/|[A-Za-z]:[\\/]|~[\\/])")
RANDOM_CALLS = {"random", "rand", "randn", "randint", "shuffle", "choice", "normal", "uniform",
                "permutation", "sample", "integers", "standard_normal"}
RANDOM_OWNERS = {"random", "rng", "generator", "gen"}
SEED_CALLS = {"seed", "manual_seed", "default_rng", "RandomState", "set_seed"}
IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
CLI_MODULES = {"argparse", "click", "typer", "fire", "optparse", "getopt"}
OUTPUT_CALLS = {"savefig", "to_csv", "to_excel", "to_json", "to_parquet", "to_hdf", "to_pickle",
                "save", "savez", "savetxt", "imwrite", "dump", "write_text", "write_bytes", "imsave"}
SYNTAX_MIN_PYTHON = {ast.NamedExpr: (3, 8), ast.Match: (3, 10), ast.TryStar: (3, 11)}
if hasattr(ast, "TypeAlias"):
    SYNTAX_MIN_PYTHON[ast.TypeAlias] = (3, 12)
PIP_MAGIC = re.compile(r"^\s*[!%]\s*pip\s+install\s+(.+)$")


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
    code: str     # dynamic_import | dynamic_unresolved | absolute_path | syntax_error | unseeded_random | cli_args | notebook_magic
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


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(_dotted(t).rsplit(".", 1)[-1] in IMPORT_ERRORS for t in types)


def _opens_for_write(node: ast.Call) -> bool:
    modes = [*node.args[1:2], *(k.value for k in node.keywords if k.arg == "mode")]
    return any(isinstance(m, ast.Constant) and set(str(m.value)) & set("wax") for m in modes)


def _is_main_guard(test: ast.AST) -> bool:
    return (
        isinstance(test, ast.Compare)
        and _dotted(test.left) == "__name__"
        and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in test.comparators)
    )


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[ImportRef] = []
        self.findings: list[Finding] = []
        self.data_refs: list[tuple[str, int]] = []
        self.method_calls: set[str] = set()
        self.has_main_guard = False
        self.random_line = 0
        self.seeded = False
        self.cli_line = 0
        self.outputs: set[str] = set()
        self._context: list[str] = []

    def _kind(self, default: str) -> str:
        if "optional" in self._context:
            return "optional"
        if "if" in self._context:
            return "conditional"
        return default

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(ImportRef(alias.name, node.lineno, self._kind("static")))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            self.imports.append(ImportRef(node.module or "", node.lineno, "relative", node.level))
        elif node.module:
            self.imports.append(ImportRef(node.module, node.lineno, self._kind("static")))

    def visit_Try(self, node: ast.Try) -> None:
        guarded = any(_catches_import_error(h) for h in node.handlers)
        self._context.append("optional" if guarded else "try")
        for child in [*node.body, *node.handlers]:
            self.visit(child)
        self._context.pop()
        for child in [*node.orelse, *node.finalbody]:
            self.visit(child)

    visit_TryStar = visit_Try

    def visit_If(self, node: ast.If) -> None:
        if _is_main_guard(node.test):
            self.has_main_guard = True
            self.generic_visit(node)
            return
        self.visit(node.test)
        self._context.append("if")
        for child in [*node.body, *node.orelse]:
            self.visit(child)
        self._context.pop()

    def visit_Call(self, node: ast.Call) -> None:
        parts = _dotted(node.func).split(".")
        last, owners = parts[-1], {p.lower() for p in parts[:-1]}
        if isinstance(node.func, ast.Attribute):
            self.method_calls.add(last)
        if last == "import_module" or parts == ["__import__"]:
            self._dynamic_import(node)
        if last in RANDOM_CALLS and owners & RANDOM_OWNERS:
            self.random_line = self.random_line or node.lineno
        if last in SEED_CALLS and (node.args or node.keywords):
            self.seeded = True
        if last in OUTPUT_CALLS or (parts == ["open"] and _opens_for_write(node)):
            self.outputs.update(a.value for a in node.args if isinstance(a, ast.Constant))
        self.generic_visit(node)

    def _dynamic_import(self, node: ast.Call) -> None:
        arg = node.args[0] if node.args else None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            self.imports.append(ImportRef(arg.value, node.lineno, "dynamic"))
            self.findings.append(Finding("dynamic_import", node.lineno, arg.value))
        else:
            source = ast.unparse(arg) if arg is not None else ""
            self.findings.append(Finding("dynamic_unresolved", node.lineno, source))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if _dotted(node) == "sys.argv":
            self.cli_line = self.cli_line or node.lineno
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if not isinstance(value, str) or "\n" in value or not 2 < len(value) < 260:
            return
        if ABSOLUTE_PATH.match(value):
            self.findings.append(Finding("absolute_path", node.lineno, value))
        elif value.lower().endswith(DATA_EXTENSIONS) and " " not in value.strip():
            self.data_refs.append((value, node.lineno))


def _min_python(tree: ast.AST) -> tuple[int, int]:
    found = [SYNTAX_MIN_PYTHON[type(n)] for n in ast.walk(tree) if type(n) in SYNTAX_MIN_PYTHON]
    return max(found, default=(3, 6))


def scan_source(path: str, text: str, pip_hints: tuple[str, ...] = ()) -> FileScan:
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        finding = Finding("syntax_error", exc.lineno or 0, exc.msg)
        return FileScan(path, (), (finding,), (), frozenset(), (3, 6), False, pip_hints)
    visitor = _Visitor()
    visitor.visit(tree)
    findings = list(visitor.findings)
    if visitor.random_line and not visitor.seeded:
        findings.append(Finding("unseeded_random", visitor.random_line, ""))
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
    )


def scan_notebook(path: str, text: str) -> FileScan:
    """Код-ячейки .ipynb склеиваются; строки-магии (!pip, %matplotlib) вырезаются, но !pip install запоминается."""
    try:
        cells = json.loads(text).get("cells", [])
    except (json.JSONDecodeError, AttributeError):
        broken = Finding("syntax_error", 0, "некорректный JSON ноутбука")
        return FileScan(path, (), (broken,), (), frozenset(), (3, 6), False)
    lines, hints = [], []
    for cell in cells:
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        for line in (source if isinstance(source, list) else source.splitlines(True)):
            magic = PIP_MAGIC.match(line)
            if magic:
                hints.extend(t for t in magic.group(1).split() if not t.startswith("-"))
            is_magic = line.lstrip().startswith(("!", "%", "?"))
            lines.append("\n" if is_magic else line.rstrip("\n") + "\n")
    scan = scan_source(path, "".join(lines), tuple(hints))
    if not hints:
        return scan
    return replace(scan, findings=scan.findings + (Finding("notebook_magic", 0, " ".join(hints)),))
