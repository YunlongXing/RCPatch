"""Shared fallback heuristics for lightweight C/C++ source abstraction."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

from rcpatch.models import Language, MemoryOperation, MemoryOperationKind, SourceLocation, SourceParameter, StatementKind

IDENTIFIER_RE = re.compile(r"\b[A-Za-z_~][A-Za-z0-9_]*\b")
CALL_RE = re.compile(r"\b(?P<name>[A-Za-z_~][A-Za-z0-9_:]*)\s*\(")
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"](?P<name>[^">]+)[">]', re.MULTILINE)
ASSIGNMENT_OPERATOR_RE = re.compile(r"(?<![=!<>+\-*/%&|^])=(?!=)|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=")
DECLARATION_RE = re.compile(
    r"^\s*(?:const\s+|static\s+|unsigned\s+|signed\s+|long\s+|short\s+|volatile\s+|struct\s+|enum\s+|union\s+|"
    r"char\s+|int\s+|float\s+|double\s+|size_t\s+|ssize_t\s+|bool\s+|void\s+|[A-Za-z_][A-Za-z0-9_:<>]*\s+)"
)
CONDITION_RE = re.compile(r"^\s*(if|while|for|switch)\s*\((?P<expr>.*)\)\s*[{]?\s*$")
RETURN_RE = re.compile(r"^\s*return\b(?P<expr>.*?);?\s*$")

C_KEYWORDS = {
    "alignas",
    "alignof",
    "asm",
    "auto",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "constexpr",
    "continue",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "explicit",
    "extern",
    "for",
    "goto",
    "if",
    "inline",
    "mutable",
    "namespace",
    "new",
    "operator",
    "private",
    "protected",
    "public",
    "register",
    "restrict",
    "return",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "template",
    "throw",
    "try",
    "typedef",
    "typename",
    "union",
    "using",
    "virtual",
    "volatile",
    "while",
}

TYPE_HINT_TOKENS = {
    "const",
    "volatile",
    "static",
    "struct",
    "enum",
    "union",
    "unsigned",
    "signed",
    "long",
    "short",
    "char",
    "int",
    "float",
    "double",
    "void",
    "size_t",
    "ssize_t",
    "bool",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "intptr_t",
    "uintptr_t",
    "ptrdiff_t",
}

ALLOCATION_NAMES = {"malloc", "calloc", "realloc", "strdup", "xmalloc", "kmalloc", "g_malloc"}
DEALLOCATION_NAMES = {"free", "delete", "g_free", "kfree"}
MEMORY_COPY_NAMES = {"memcpy", "memmove", "strcpy", "strncpy", "strlcpy"}
MEMORY_SET_NAMES = {"memset", "bzero"}
MEMORY_COMPARE_NAMES = {"memcmp", "strcmp", "strncmp"}
MEMBER_ACCESS_RE = re.compile(r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>->|\.)\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)")
INDEX_ACCESS_RE = re.compile(r"\b(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\[(?P<index>[^\]]+)\]")
MACRO_REFERENCE_RE = re.compile(r"\b[A-Z_][A-Z0-9_]{2,}\b")


def detect_language(path: str) -> Language:
    """Infer language from a file extension."""
    extension = Path(path).suffix.lower()
    if extension in {".c", ".h"}:
        return Language.C
    if extension in {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}:
        return Language.CPP
    return Language.C_CPP


def strip_comments_preserve_layout(source: str) -> str:
    """Remove comments while preserving line numbers and offsets as much as possible."""
    result: list[str] = []
    index = 0
    in_line_comment = False
    in_block_comment = False
    in_string = False
    in_char = False

    while index < len(source):
        current = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""

        if in_line_comment:
            if current == "\n":
                in_line_comment = False
                result.append(current)
            else:
                result.append(" ")
            index += 1
            continue

        if in_block_comment:
            if current == "*" and next_char == "/":
                result.extend("  ")
                index += 2
                in_block_comment = False
            else:
                result.append("\n" if current == "\n" else " ")
                index += 1
            continue

        if in_string:
            result.append(current)
            if current == "\\" and next_char:
                result.append(next_char)
                index += 2
                continue
            if current == '"':
                in_string = False
            index += 1
            continue

        if in_char:
            result.append(current)
            if current == "\\" and next_char:
                result.append(next_char)
                index += 2
                continue
            if current == "'":
                in_char = False
            index += 1
            continue

        if current == "/" and next_char == "/":
            in_line_comment = True
            result.extend("  ")
            index += 2
            continue
        if current == "/" and next_char == "*":
            in_block_comment = True
            result.extend("  ")
            index += 2
            continue
        if current == '"':
            in_string = True
            result.append(current)
            index += 1
            continue
        if current == "'":
            in_char = True
            result.append(current)
            index += 1
            continue

        result.append(current)
        index += 1

    return "".join(result)


def extract_includes(source: str) -> list[str]:
    """Extract include directives from a source file."""
    return [match.group("name") for match in INCLUDE_RE.finditer(source)]


def split_top_level(text: str, separator: str = ",") -> list[str]:
    """Split text on a separator while ignoring nested delimiters."""
    parts: list[str] = []
    current: list[str] = []
    depth_paren = 0
    depth_angle = 0
    depth_bracket = 0
    depth_brace = 0

    for char in text:
        if char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren = max(depth_paren - 1, 0)
        elif char == "<":
            depth_angle += 1
        elif char == ">":
            depth_angle = max(depth_angle - 1, 0)
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket = max(depth_bracket - 1, 0)
        elif char == "{":
            depth_brace += 1
        elif char == "}":
            depth_brace = max(depth_brace - 1, 0)

        if (
            char == separator
            and depth_paren == 0
            and depth_angle == 0
            and depth_bracket == 0
            and depth_brace == 0
        ):
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_parameters(raw_params: str) -> list[SourceParameter]:
    """Convert a function parameter string into approximate parameter models."""
    stripped = raw_params.strip()
    if not stripped or stripped == "void":
        return []

    parameters: list[SourceParameter] = []
    for index, parameter_text in enumerate(split_top_level(stripped, ",")):
        tokens = IDENTIFIER_RE.findall(parameter_text)
        name: Optional[str] = None
        type_hint: Optional[str] = None
        if tokens:
            candidate = tokens[-1]
            if not _is_probable_type_name(candidate) and not candidate.isupper():
                name = candidate
                split_index = parameter_text.rfind(candidate)
                type_hint = parameter_text[:split_index].strip() or None
            else:
                type_hint = parameter_text.strip()

        parameters.append(
            SourceParameter(
                position=index,
                name=name,
                raw_declaration=parameter_text,
                type_hint=type_hint,
            )
        )
    return parameters


def extract_call_names(text: str) -> list[str]:
    """Extract function-like calls from a statement."""
    calls: list[str] = []
    for match in CALL_RE.finditer(text):
        name = match.group("name")
        short_name = name.split("::")[-1]
        if short_name in C_KEYWORDS:
            continue
        calls.append(name)
    return _deduplicate(calls)


def extract_call_argument_metadata(text: str, call_names: Optional[list[str]] = None) -> dict[str, object]:
    """Extract lightweight call argument metadata for later interprocedural hints."""

    argument_map: dict[str, list[str]] = {}
    argument_variables: list[str] = []
    for call_name in call_names or extract_call_names(text):
        arguments = _call_arguments_for(text, call_name.split("::")[-1])
        if not arguments and "::" in call_name:
            arguments = _call_arguments_for(text, call_name)
        if not arguments:
            continue
        argument_map[call_name] = arguments
        for argument in arguments:
            argument_variables.extend(
                identifier
                for identifier in IDENTIFIER_RE.findall(argument)
                if identifier not in C_KEYWORDS and not _is_probable_type_name(identifier)
            )
    return {
        "call_arguments": argument_map,
        "call_argument_variables": _deduplicate(argument_variables),
    }


def extract_macro_references(text: str) -> list[str]:
    """Return probable macro or constant-like identifiers from a statement."""

    return _deduplicate(
        macro
        for macro in MACRO_REFERENCE_RE.findall(text)
        if macro not in C_KEYWORDS and not _is_probable_type_name(macro)
    )


def has_assignment(text: str) -> bool:
    """Detect whether a statement contains an assignment-like operator."""
    return ASSIGNMENT_OPERATOR_RE.search(text) is not None


def extract_defined_variables(text: str) -> list[str]:
    """Approximate variables defined on the left-hand side of an assignment or declaration."""
    match = ASSIGNMENT_OPERATOR_RE.search(text)
    if match is None:
        return []
    left_side = text[: match.start()]
    index_match = INDEX_ACCESS_RE.search(left_side)
    if index_match is not None:
        return [index_match.group("base")]
    member_match = MEMBER_ACCESS_RE.search(left_side)
    if member_match is not None:
        return _deduplicate([member_match.group("base"), member_match.group("field")])
    identifiers = [identifier for identifier in IDENTIFIER_RE.findall(left_side) if identifier not in C_KEYWORDS]
    if not identifiers:
        return []
    return _deduplicate([identifiers[-1]])


def extract_declared_variables(text: str) -> list[str]:
    """Approximate variables declared by a declaration statement."""
    if DECLARATION_RE.match(text) is None:
        return []
    if "(" in text and ")" in text and text.strip().endswith("{"):
        return []

    declaration = text.rstrip(";")
    parts = split_top_level(declaration, ",")
    names: list[str] = []
    for part in parts:
        assignment_match = ASSIGNMENT_OPERATOR_RE.search(part)
        left_side = part[: assignment_match.start()] if assignment_match is not None else part
        identifiers = [
            identifier
            for identifier in IDENTIFIER_RE.findall(left_side)
            if not _is_probable_type_name(identifier)
        ]
        if identifiers:
            names.append(identifiers[-1])
    return _deduplicate(names)


def extract_referenced_variables(
    text: str,
    *,
    excluded: Optional[Iterable[str]] = None,
) -> list[str]:
    """Approximate identifiers referenced in a statement."""
    excluded_names = set(excluded or [])
    identifiers = []
    for identifier in IDENTIFIER_RE.findall(text):
        if identifier in C_KEYWORDS:
            continue
        if _is_probable_type_name(identifier):
            continue
        if identifier in excluded_names:
            continue
        if identifier.isupper():
            continue
        identifiers.append(identifier)
    return _deduplicate(identifiers)


def extract_structural_accesses(text: str) -> dict[str, list[str]]:
    """Extract approximate field, index, pointer, and alias structure from a statement."""

    field_accesses: list[str] = []
    field_bases: list[str] = []
    for match in MEMBER_ACCESS_RE.finditer(text):
        base = match.group("base")
        field = match.group("field")
        field_bases.append(base)
        field_accesses.append(f"{base}{match.group('op')}{field}")

    index_accesses: list[str] = []
    index_bases: list[str] = []
    index_variables: list[str] = []
    for match in INDEX_ACCESS_RE.finditer(text):
        base = match.group("base")
        index_expr = match.group("index").strip()
        index_bases.append(base)
        index_accesses.append(f"{base}[{index_expr}]")
        index_variables.extend(
            identifier
            for identifier in IDENTIFIER_RE.findall(index_expr)
            if identifier not in C_KEYWORDS and not _is_probable_type_name(identifier)
        )

    lhs, rhs = _split_assignment_sides(text)
    alias_sources: list[str] = []
    if lhs and rhs:
        rhs_ids = [
            identifier
            for identifier in IDENTIFIER_RE.findall(rhs)
            if identifier not in C_KEYWORDS and not _is_probable_type_name(identifier)
        ]
        # Pointer aliases and shallow copies are high-value for RCPatch's
        # approximate ownership/lifetime reasoning.
        if "*" in lhs or "*" in rhs or "&" in rhs or "->" in rhs or "." in rhs:
            alias_sources.extend(rhs_ids)

    pointer_dereferences = [
        identifier
        for identifier in re.findall(r"(?<![A-Za-z0-9_])\*\s*([A-Za-z_][A-Za-z0-9_]*)", text)
        if identifier not in C_KEYWORDS and not _is_probable_type_name(identifier)
    ]

    return {
        "field_accesses": _deduplicate(field_accesses),
        "field_bases": _deduplicate(field_bases),
        "index_accesses": _deduplicate(index_accesses),
        "index_bases": _deduplicate(index_bases),
        "index_variables": _deduplicate(index_variables),
        "alias_sources": _deduplicate(alias_sources),
        "pointer_dereferences": _deduplicate(pointer_dereferences),
        "macro_references": extract_macro_references(text),
    }


def detect_condition_expression(text: str) -> Optional[str]:
    """Extract a condition expression if the statement looks like a control predicate."""
    match = CONDITION_RE.match(text.strip())
    if match is None:
        return None
    return match.group("expr").strip() or None


def _is_probable_type_name(identifier: str) -> bool:
    if identifier in TYPE_HINT_TOKENS:
        return True
    if re.fullmatch(r"[iu]?int\d+_t", identifier):
        return True
    if identifier.endswith("_t"):
        return True
    return False


def detect_return_expression(text: str) -> Optional[str]:
    """Extract a return expression if present."""
    match = RETURN_RE.match(text.strip())
    if match is None:
        return None
    expression = match.group("expr").strip()
    return expression or None


def detect_statement_types(text: str, *, call_names: list[str], memory_operations: list[MemoryOperation]) -> list[StatementKind]:
    """Classify a statement into approximate categories."""
    statement_types: list[StatementKind] = []
    stripped = text.strip()
    if has_assignment(stripped):
        statement_types.append(StatementKind.ASSIGNMENT)
    if detect_condition_expression(stripped) is not None:
        statement_types.append(StatementKind.CONDITION)
    if stripped.startswith("return"):
        statement_types.append(StatementKind.RETURN)
    if call_names:
        statement_types.append(StatementKind.FUNCTION_CALL)
    if memory_operations:
        statement_types.append(StatementKind.MEMORY_OPERATION)
    if extract_declared_variables(stripped):
        statement_types.append(StatementKind.DECLARATION)
    if not statement_types:
        statement_types.append(StatementKind.UNKNOWN)
    return _deduplicate(statement_types)


def extract_memory_operations(
    text: str,
    *,
    location: SourceLocation,
    call_names: Optional[list[str]] = None,
) -> list[MemoryOperation]:
    """Detect allocation, free-like, and memory helper operations."""
    normalized_calls = [call.split("::")[-1] for call in (call_names or extract_call_names(text))]
    operations: list[MemoryOperation] = []

    for call_name in normalized_calls:
        if call_name in ALLOCATION_NAMES:
            kind = MemoryOperationKind.REALLOCATION if call_name == "realloc" else MemoryOperationKind.ALLOCATION
            operations.append(
                MemoryOperation(
                    kind=kind,
                    function_name=call_name,
                    location=location,
                    target=_first_target(text),
                    size_expression=_first_argument(text, call_name, prefer_last=call_name in {"malloc", "calloc", "realloc"}),
                )
            )
        elif call_name in DEALLOCATION_NAMES:
            operations.append(
                MemoryOperation(
                    kind=MemoryOperationKind.DEALLOCATION,
                    function_name=call_name,
                    location=location,
                    target=_first_argument(text, call_name),
                )
            )
        elif call_name in MEMORY_COPY_NAMES:
            operations.append(
                MemoryOperation(
                    kind=MemoryOperationKind.COPY,
                    function_name=call_name,
                    location=location,
                    target=_first_argument(text, call_name),
                    size_expression=_first_argument(text, call_name, prefer_last=True),
                )
            )
        elif call_name in MEMORY_SET_NAMES:
            operations.append(
                MemoryOperation(
                    kind=MemoryOperationKind.SET,
                    function_name=call_name,
                    location=location,
                    target=_first_argument(text, call_name),
                    size_expression=_first_argument(text, call_name, prefer_last=True),
                )
            )
        elif call_name in MEMORY_COMPARE_NAMES:
            operations.append(
                MemoryOperation(
                    kind=MemoryOperationKind.COMPARE,
                    function_name=call_name,
                    location=location,
                    target=_first_argument(text, call_name),
                )
            )

    stripped = text.strip()
    if re.search(r"\bnew\b", stripped):
        operations.append(
            MemoryOperation(
                kind=MemoryOperationKind.ALLOCATION,
                function_name="new",
                location=location,
                target=_first_target(stripped),
            )
        )
    if re.search(r"\bdelete\b", stripped):
        operations.append(
            MemoryOperation(
                kind=MemoryOperationKind.DEALLOCATION,
                function_name="delete",
                location=location,
                target=_first_argument(stripped, "delete"),
            )
        )

    unique: list[MemoryOperation] = []
    seen: set[tuple[str, str, int]] = set()
    for operation in operations:
        key = (operation.kind.value, operation.function_name, operation.location.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(operation)
    return unique


def _first_target(text: str) -> Optional[str]:
    defined = extract_defined_variables(text)
    if defined:
        return defined[0]
    return None


def _first_argument(text: str, callee_name: str, *, prefer_last: bool = False) -> Optional[str]:
    arguments = _call_arguments_for(text, callee_name)
    if not arguments:
        return None
    return arguments[-1].strip() if prefer_last else arguments[0].strip()


def _call_arguments_for(text: str, callee_name: str) -> list[str]:
    pattern = re.compile(re.escape(callee_name) + r"\s*\((?P<args>.*)\)")
    match = pattern.search(text)
    if match is None:
        return []
    return [argument.strip() for argument in split_top_level(match.group("args"), ",") if argument.strip()]


def _split_assignment_sides(text: str) -> tuple[Optional[str], Optional[str]]:
    match = ASSIGNMENT_OPERATOR_RE.search(text)
    if match is None:
        return None, None
    return text[: match.start()].strip(), text[match.end() :].strip().rstrip(";")


def make_statement_location(
    *,
    file_path: str,
    line: int,
    column: Optional[int],
    function_name: str,
    snippet: str,
) -> SourceLocation:
    """Build a normalized SourceLocation for a statement."""
    return SourceLocation(
        file=file_path,
        line=line,
        column=column,
        function=function_name,
        snippet=snippet,
    )


def _deduplicate(items: Iterable) -> list:
    seen = set()
    result = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
