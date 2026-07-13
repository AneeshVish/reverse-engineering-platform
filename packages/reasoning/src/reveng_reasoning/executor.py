"""Single-rule execution.

Runs one rule through the ``guard`` boundary so no raw exception escapes,
normalizing the outcome into a ``RuleResult`` stamped with the rule identifier. A
raised exception becomes an empty result (the rule produced nothing).
"""

from __future__ import annotations

from .errors import guard
from .rules import Rule, RuleContext, RuleResult

__all__ = ["RuleExecutor"]


class RuleExecutor:
    """Executes a single rule and produces a normalized result."""

    def execute(self, rule: Rule, context: RuleContext) -> RuleResult:
        identifier = rule.metadata.identifier
        outcome = guard(lambda: rule.apply(context))
        if outcome.ok:
            produced = outcome.value
            if isinstance(produced, RuleResult):
                return RuleResult(rule_id=identifier, inferences=produced.inferences)
            return RuleResult(rule_id=identifier, inferences=())
        return RuleResult(rule_id=identifier, inferences=())
