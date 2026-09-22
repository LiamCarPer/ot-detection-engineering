"""Loki logsource routing for the generated LogQL queries.

pySigma's Loki backend does not encode the Sigma logsource into the LogQL stream
selector: by default every rule matches ``{job=~".+"}``, so in a deployment that
ships several protocols into one Loki instance a rule can match another
protocol's events — a Modbus write rule firing on DNP3 function codes, for
example. The selector, not the rule fields, is what should route an event.

The backend exposes a ``logsource_loki_selection`` custom attribute for exactly
this. This pipeline sets it from the rule's logsource service so the generated
query selects the stream the rule is meant to run on::

    {job=~".+", service="modbus"} | logfmt | ...

Correlation rules have no logsource of their own: their subquery is generated
from the rules they reference, and the backend reads the selector from those
referenced rules. The transformation therefore pushes the selector down to the
referenced rules rather than onto the correlation rule, and refuses to guess when
the references span several streams — silently falling back to ``{job=~".+"}``
would reintroduce exactly the bug this pipeline exists to prevent, one layer up.

Deployments must label their Loki streams with the ``service`` label defined in
``docs/TELEMETRY.md``; see ``docs/DEPLOY.md``.
"""

from __future__ import annotations

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import PreprocessingTransformation
from sigma.rule import SigmaRule

LOGSOURCE_ATTRIBUTE = "logsource_loki_selection"


class CorrelationLogsourceError(RuntimeError):
    """Raised when a correlation rule's stream cannot be derived unambiguously."""


class LokiLogsourceSelection(PreprocessingTransformation):
    """Set the Loki stream selector from the rule's logsource service."""

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        if isinstance(rule, SigmaCorrelationRule):
            self._apply_to_referenced_rules(rule)
            return
        service = rule.logsource.service
        if service:
            rule.custom_attributes[LOGSOURCE_ATTRIBUTE] = self._selector(service)

    @staticmethod
    def _selector(service: str) -> str:
        return f'{{job=~".+", service="{service}"}}'

    def _apply_to_referenced_rules(self, rule: SigmaCorrelationRule) -> None:
        referenced = list(rule.referenced_rules)
        if not referenced or any(reference.rule is None for reference in referenced):
            raise CorrelationLogsourceError(
                f"correlation rule '{rule.title}' has unresolved rule references; "
                "load the whole ruleset before converting so references resolve"
            )
        services = {reference.rule.logsource.service for reference in referenced}
        if len(services) != 1:
            listed = ", ".join(sorted(str(service) for service in services))
            raise CorrelationLogsourceError(
                f"correlation rule '{rule.title}' references {len(services)} streams "
                f"({listed}); a Loki stream selector cannot be derived from more than one, "
                "and guessing would let the subquery match every stream"
            )
        service = services.pop()
        if not service:
            raise CorrelationLogsourceError(
                f"correlation rule '{rule.title}' references rules without a logsource "
                "service, so no Loki stream selector can be derived"
            )
        for reference in referenced:
            reference.rule.custom_attributes[LOGSOURCE_ATTRIBUTE] = self._selector(service)


LOKI_LOGSOURCE_PIPELINE = ProcessingPipeline(
    [ProcessingItem(LokiLogsourceSelection())],
    name="ot-loki-logsource",
)
