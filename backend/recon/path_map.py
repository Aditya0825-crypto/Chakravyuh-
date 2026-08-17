"""Build sink → caller → input-source path maps."""

from __future__ import annotations

from dataclasses import dataclass

from recon.call_graph import FunctionInfo, INPUT_SOURCE_CALLS


@dataclass
class PathMapEntry:
    function: str
    file: str
    line: int
    sinks: list[str]
    call_path: str
    input_sources: list[str]
    reachable_from_main: bool


def build_path_map(functions: dict[str, FunctionInfo]) -> list[PathMapEntry]:
    """Map functions with dangerous sinks to call paths and input sources."""
    reverse: dict[str, set[str]] = {name: set() for name in functions}
    for name, info in functions.items():
        for callee in info.calls:
            if callee in reverse:
                reverse[callee].add(name)

    entries: list[PathMapEntry] = []
    for name, info in functions.items():
        if not info.sinks:
            continue
        path = _build_call_path(name, reverse, functions)
        inputs = _collect_input_sources(name, functions, reverse)
        if "main" in functions and name != "main":
            reachable = _reachable_from("main", name, functions)
        else:
            reachable = name == "main" or bool(inputs)

        entries.append(
            PathMapEntry(
                function=name,
                file=info.file,
                line=info.line,
                sinks=sorted(info.sinks),
                call_path=path,
                input_sources=sorted(inputs) if inputs else ["unknown input"],
                reachable_from_main=reachable,
            )
        )

    return entries


def _build_call_path(
    target: str,
    reverse: dict[str, set[str]],
    functions: dict[str, FunctionInfo],
    max_depth: int = 6,
) -> str:
    """Build call path from entry point toward target."""
    if target == "main":
        return "main()"

    chain = _path_to_main(target, reverse, max_depth)
    if chain:
        return " → ".join(f"{n}()" for n in reversed(chain))

    # Fallback: direct callers
    callers = reverse.get(target, set())
    if callers:
        caller = sorted(callers)[0]
        return f"{caller}() → {target}()"
    return f"{target}()"


def _path_to_main(
    target: str,
    reverse: dict[str, set[str]],
    max_depth: int,
) -> list[str] | None:
    queue: list[tuple[str, list[str]]] = [(target, [target])]
    visited: set[str] = set()

    while queue:
        node, path = queue.pop(0)
        if len(path) > max_depth:
            continue
        if node in visited:
            continue
        visited.add(node)
        if node == "main":
            return path
        for caller in reverse.get(node, set()):
            queue.append((caller, path + [caller]))
    return None


def _collect_input_sources(
    target: str,
    functions: dict[str, FunctionInfo],
    reverse: dict[str, set[str]],
) -> set[str]:
    sources: set[str] = set()
    info = functions.get(target)
    if info:
        sources |= info.input_sources

    # Propagate input sources from callers (data flows down)
    for caller in reverse.get(target, set()):
        caller_info = functions.get(caller)
        if caller_info:
            sources |= caller_info.input_sources

    # main with getline/argv
    if target == "main":
        sources.add("stdin stream")

    return sources


def _reachable_from(start: str, target: str, functions: dict[str, FunctionInfo]) -> bool:
    if start == target:
        return True
    visited: set[str] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node in visited:
            continue
        visited.add(node)
        if node == target:
            return True
        info = functions.get(node)
        if not info:
            continue
        for callee in info.calls:
            if callee in functions:
                stack.append(callee)
    return False
