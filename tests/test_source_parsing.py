"""Tests for the lightweight source parsing and program abstraction layer."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.models import MemoryOperationKind, ParserBackend, StatementKind
from rcpatch.source import SourceProjectParser


FOO_C = """\
#include <stdlib.h>
#include <string.h>

static int helper(int size) {
    int len = size + 4;
    if (len > 128) {
        return -1;
    }
    return len;
}

char *make_buffer(int n) {
    int len = helper(n);
    char *buf = (char *)malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf, 0, len);
    return buf;
}

void release_buffer(char *buf) {
    free(buf);
}
"""

BAR_C = """\
extern char *make_buffer(int n);
void release_buffer(char *buf);

void do_work(int input) {
    char *ptr = make_buffer(input);
    if (ptr != NULL) {
        memcpy(ptr, "AAAA", 4);
    }
    release_buffer(ptr);
}
"""

OVERLOADED_CPP = """\
int A::foo() { return 1; } int B::foo() { return 2; }
"""


class SourceParsingTests(unittest.TestCase):
    def test_regex_backend_extracts_functions_calls_and_memory_ops(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "foo.c").write_text(FOO_C, encoding="utf-8")
            (src_root / "bar.c").write_text(BAR_C, encoding="utf-8")

            parser = SourceProjectParser()
            program = parser.parse_repository(repo_root, preferred_backend=ParserBackend.REGEX)

            self.assertEqual(program.backend, ParserBackend.REGEX)
            self.assertEqual(len(program.files), 2)
            self.assertEqual(len(program.functions), 4)

            names = {function.name for function in program.functions}
            self.assertEqual(names, {"helper", "make_buffer", "release_buffer", "do_work"})

            make_buffer = next(function for function in program.functions if function.name == "make_buffer")
            statement_types = {statement_type for statement in make_buffer.statements for statement_type in statement.statement_types}
            self.assertIn(StatementKind.ASSIGNMENT, statement_types)
            self.assertIn(StatementKind.CONDITION, statement_types)
            self.assertIn(StatementKind.RETURN, statement_types)

            memory_kinds = {operation.kind for operation in make_buffer.memory_operations}
            self.assertIn(MemoryOperationKind.ALLOCATION, memory_kinds)
            self.assertIn(MemoryOperationKind.SET, memory_kinds)

            resolved_edges = {
                (relationship.caller_name, relationship.callee_name, relationship.resolved_target is not None)
                for relationship in program.call_relationships
            }
            self.assertIn(("make_buffer", "helper", True), resolved_edges)
            self.assertIn(("do_work", "release_buffer", True), resolved_edges)

            index = parser.build_index(program)
            do_work = next(function for function in program.functions if function.name == "do_work")
            callees = index.callees_of(do_work.function_id)
            self.assertIn("make_buffer", callees)
            self.assertIn("release_buffer", callees)

    def test_tree_sitter_preference_falls_back_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "foo.c").write_text(FOO_C, encoding="utf-8")

            parser = SourceProjectParser()
            program = parser.parse_repository(repo_root, preferred_backend=ParserBackend.TREE_SITTER)

            self.assertEqual(program.backend, ParserBackend.REGEX)
            self.assertTrue(
                any("tree-sitter backend" in approximation for approximation in program.approximations)
            )

    def test_regex_backend_generates_unique_function_ids_for_same_line_same_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "dup.cpp").write_text(OVERLOADED_CPP, encoding="utf-8")

            parser = SourceProjectParser()
            program = parser.parse_repository(repo_root, preferred_backend=ParserBackend.REGEX)

            foo_functions = [function for function in program.functions if function.name == "foo"]
            self.assertEqual(len(foo_functions), 2)
            self.assertEqual(len({function.function_id for function in foo_functions}), 2)
            self.assertTrue(all(function.function_id.startswith("src/dup.cpp:foo:1:") for function in foo_functions))


if __name__ == "__main__":
    unittest.main()
