### IMPORTS
### ============================================================================
# Future
from __future__ import annotations

# Standard Library
from typing import Any

# Local
from ..elastic import ElasticsearchClient
from ..report import AggregateReport, ForensicReport
from .base import BaseConfig, Sink


### CLASSES
### ============================================================================
class Elasticsearch(Sink):

    config: ElasticsearchConfig

    def setup(self) -> None:
        self.client = ElasticsearchClient(**self.config.client)
        self.client.migrate_indexes()
        return

    def cleanup(self) -> None:
        self.client.client.close()
        return

    def process_aggregate_report(self, report: AggregateReport) -> None:
        self.client.save_aggregate_report_to_elasticsearch(report)
        return

    def process_forensic_report(self, report: ForensicReport) -> None:
        self.client.save_forensic_report_to_elasticsearch(report)
        return


class ElasticsearchConfig(BaseConfig):
    # As per https://elasticsearch-py.readthedocs.io/en/v8.13.0/api/elasticsearch.html
    client: dict[str, Any]
