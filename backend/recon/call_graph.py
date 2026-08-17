"""tree-sitter C call graph extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Node, Parser

C_LANGUAGE = Language(tsc.language())
PARSER = Parser(C_LANGUAGE)

SOURCE_EXTS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"}


@dataclass
class FunctionInfo:
    name: str
    file: str
    line: int
    end_line: int
    params: list[str] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)
    sinks: set[str] = field(default_factory=set)
    input_sources: set[str] = field(default_factory=set)


DANGEROUS_SINKS = {
    "strcpy", "strcat", "sprintf", "gets", "system", "popen",
    "scanf", "vsprintf", "strncpy", "memcpy", "memmove",
}

INPUT_SOURCE_CALLS = {
    "read", "recv", "recvfrom", "getline", "fgets", "fread",
    "scanf", "getchar", "accept", "SSL_read",
}


def extract_call_graph(source_root: Path) -> dict[str, FunctionInfo]:
    """Parse all C/C++ files and build a function → metadata map."""
    functions: dict[str, FunctionInfo] = {}

    for path in sorted(source_root.rglob("*")):
        if path.suffix.lower() not in SOURCE_EXTS or not path.is_file():
            continue
        rel = _rel_path(path, source_root)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_funcs = _parse_file(source, rel)
        for fn in file_funcs.values():
            if fn.name in functions:
                existing = functions[fn.name]
                existing.calls |= fn.calls
                existing.sinks |= fn.sinks
                existing.input_sources |= fn.input_sources
            else:
                functions[fn.name] = fn

    return functions


def _rel_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.name


def _parse_file(source: str, rel_file: str) -> dict[str, FunctionInfo]:
    tree = PARSER.parse(source.encode("utf-8"))
    root = tree.root_node
    funcs: dict[str, FunctionInfo] = {}

    for node in _walk(root):
        if node.type == "function_definition":
            info = _parse_function(node, source, rel_file)
            if info:
                funcs[info.name] = info
                _analyze_calls(node, source, info)

    return funcs


def _parse_function(node: Node, source: str, rel_file: str) -> FunctionInfo | None:
    decl = node.child_by_field_name("declarator")
    if not decl:
        return None
    name_node = _find_function_name(decl)
    if not name_node:
        return None
    name = source[name_node.start_byte : name_node.end_byte]
    line = node.start_point[0] + 1
    end_line = node.end_point[0] + 1
    params = _extract_params(decl, source)
    return FunctionInfo(
        name=name,
        file=rel_file,
        line=line,
        end_line=end_line,
        params=params,
    )


def _find_function_name(node: Node) -> Node | None:
    if node.type in ("identifier", "field_identifier"):
        return node
    for child in node.children:
        found = _find_function_name(child)
        if found:
            return found
    return None


def _extract_params(decl: Node, source: str) -> list[str]:
    params: list[str] = []
    for child in _walk(decl):
        if child.type == "parameter_declaration":
            text = source[child.start_byte : child.end_byte].strip()
            if text:
                params.append(text.split()[-1].replace("*", "").strip())
    return params


def _analyze_calls(func_node: Node, source: str, info: FunctionInfo) -> None:
    body = func_node.child_by_field_name("body")
    if not body:
        return
    for node in _walk(body):
        if node.type == "call_expression":
            fn_node = node.child_by_field_name("function")
            if not fn_node:
                continue
            callee = source[fn_node.start_byte : fn_node.end_byte].strip()
            base = callee.split("->")[-1].split(".")[-1]
            info.calls.add(base)
            if base in DANGEROUS_SINKS:
                info.sinks.add(base)
            if base in INPUT_SOURCE_CALLS:
                info.input_sources.add(_input_label(base))


def _input_label(call: str) -> str:
    labels = {
        "read": "file/socket read",
        "recv": "network socket",
        "recvfrom": "network socket",
        "getline": "stdin stream",
        "fgets": "file/stream input",
        "fread": "file input",
        "scanf": "formatted stdin",
        "accept": "network connection",
        "SSL_read": "TLS socket",
    }
    return labels.get(call, call)


def _walk(node: Node):
    yield node
    for child in node.children:
        yield from _walk(child)
