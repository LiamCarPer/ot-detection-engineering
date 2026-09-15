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

Deployments must label their Loki streams with the ``service`` label defined in
``docs/TELEMETRY.md``; see ``docs/DEPLOY.md``.
"""

from __future__ import annotations

from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import PreprocessingTransformation
from sigma.rule import SigmaRule

LOGSOURCE_ATTRIBUTE = "logsource_loki_selection"


class LokiLogsourceSelection(PreprocessingTransformation):
    """Set the Loki stream selector from the rule's logsource service."""

    def apply(self, rule: SigmaRule) -> None:
        super().apply(rule)
        service = rule.logsource.service
        if service:
            rule.custom_attributes[LOGSOURCE_ATTRIBUTE] = f'{{job=~".+", service="{service}"}}'


LOKI_LOGSOURCE_PIPELINE = ProcessingPipeline(
    [ProcessingItem(LokiLogsourceSelection())],
    name="ot-loki-logsource",
)
