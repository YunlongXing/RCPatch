"""Tests for trigger-guided backward slicing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rcpatch.models import DependencyRelation, ParserBackend, SourceLocation, TriggerPoint, TriggerType
from rcpatch.source import SourceProjectParser
from rcpatch.slicing import HybridBackwardSlicer


SAMPLE_SOURCE = """\
#include <stdlib.h>
#include <string.h>

int compute_size(int n) {
    int len = n + 4;
    return len;
}

char *make_buffer(int input) {
    int len = compute_size(input);
    char *buf = (char *)malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    memset(buf, 0, len);
    return buf;
}

void do_work(int input) {
    char *ptr = make_buffer(input);
    if (ptr != NULL) {
        memcpy(ptr, "AAAA", input);
    }
}
"""


class BackwardSliceTests(unittest.TestCase):
    def test_hybrid_backward_slicer_collects_intraprocedural_and_interprocedural_causes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = Path(temp_dir) / "repo"
            src_root = repo_root / "src"
            src_root.mkdir(parents=True)
            (src_root / "sample.c").write_text(SAMPLE_SOURCE, encoding="utf-8")

            parser = SourceProjectParser()
            program = parser.parse_repository(repo_root, preferred_backend=ParserBackend.REGEX)
            index = parser.build_index(program)

            trigger = TriggerPoint(
                location=SourceLocation(
                    file="src/sample.c",
                    line=20,
                    function="do_work",
                ),
                type=TriggerType.CRASH_LINE,
                failing_operation="memcpy",
            )

            slicer = HybridBackwardSlicer(max_interprocedural_hops=3)
            slice_result = slicer.slice_from_trigger(index, trigger)

            node_texts = {node.text for node in slice_result.nodes}
            self.assertIn('memcpy(ptr, "AAAA", input);', node_texts)
            self.assertIn('char *ptr = make_buffer(input);', node_texts)
            self.assertIn('if (ptr != NULL) {', node_texts)
            self.assertIn('return buf;', node_texts)
            self.assertIn('char *buf = (char *)malloc(len);', node_texts)
            self.assertIn('int len = compute_size(input);', node_texts)
            self.assertIn('int len = n + 4;', node_texts)

            relations = {(edge.relation, edge.entity) for edge in slice_result.edges}
            self.assertIn((DependencyRelation.CONTROL_DEPENDENCE, "ptr != NULL"), relations)
            self.assertIn((DependencyRelation.RETURN_VALUE, "make_buffer"), relations)
            self.assertIn((DependencyRelation.ALLOCATION_SITE, "buf"), relations)
            self.assertIn((DependencyRelation.INTEGER_INFLUENCE, "len"), relations)
            self.assertIn((DependencyRelation.CALL_ARGUMENT, "input"), relations)

            self.assertTrue(slice_result.approximations)
            self.assertEqual(slice_result.trigger_node_id, next(node.node_id for node in slice_result.nodes if node.is_trigger))


if __name__ == "__main__":
    unittest.main()
