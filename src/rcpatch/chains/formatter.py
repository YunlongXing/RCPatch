"""Human-readable formatting for constructed causality chains."""

from __future__ import annotations

from typing import Iterable

from rcpatch.models import CausalityChain


class ChainTextFormatter:
    """Render chain objects into compact human-readable text."""

    def format_chain(self, chain: CausalityChain) -> str:
        """Format a single causality chain."""
        header = f"Chain {chain.rank or '?'}"
        if chain.root_cause_rank is not None:
            header += f" (root candidate #{chain.root_cause_rank}, score {chain.score:.2f})"
        else:
            header += f" (score {chain.score:.2f})"

        lines = [header]
        for index, step in enumerate(chain.steps, start=1):
            entity_text = f" [{step.entity}]" if step.entity else ""
            operation_type = step.metadata.get("operation_type", "statement")
            location_text = f"{step.location.file}:{step.location.line}"
            if step.location.function:
                location_text += f" in {step.location.function}"
            lines.append(
                f"{index}. {location_text} | {operation_type} | {step.relation.value}{entity_text}: {step.explanation}"
            )
        lines.append(f"Summary: {chain.summary}")
        return "\n".join(lines)

    def format_chains(self, chains: Iterable[CausalityChain]) -> str:
        """Format multiple chains separated by blank lines."""
        return "\n\n".join(self.format_chain(chain) for chain in chains)
