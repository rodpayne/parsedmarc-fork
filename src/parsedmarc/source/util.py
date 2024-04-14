"""Utitily Sources

These Sources are not intended to be used in production.
"""

### IMPORTS
### ============================================================================
## Future
from __future__ import annotations

## Standard Library
from copy import deepcopy
import random
import time
from typing import Any
import uuid

## Installed

## Application
from .base import Source, SourceState, BaseConfig, Job

from ..reports import Report, AggregateReport, ForensicReport


### CLASSES
### ============================================================================
class UtilitySource(Source):
    """Base class for utility sources.

    This class should not be used directly.

    Child classes MUST implement `self.make_report`.
    """

    config: UtilityConfig

    def get_job(self) -> Job:
        if self._state != SourceState.RUNNING:
            raise RuntimeError("Source is not running")

        self.sleep()
        job = Job(source=self, report=self.make_report(), identifier=str(uuid.uuid4()))
        self.register_job(job)
        return job

    def make_report(self) -> Report:
        raise NotImplementedError("Child classes must implement make_report")

    def sleep(self) -> None:
        """Sleep for the configured time"""
        sleep_time: int | float | None
        if self.config.sleep_enabled:
            if (sleep_time := self.config.sleep_time) is None:
                sleep_time = random.uniform(self.config.sleep_min, self.config.sleep_max)
            time.sleep(sleep_time)
        return


class UtilityConfig(BaseConfig):
    sleep_enabled: bool = True
    sleep_time: int | None = None
    sleep_min: int | float = 0.2
    sleep_max: int | float = 1.5


class ReportConfig(UtilityConfig):
    report: dict[str, Any] | None = None


## DMARC Reports
## -----------------------------------------------------------------------------
# Aggregate Reports
# ..............................................................................
class StaticAggregateReportGenerator(UtilitySource):
    """Source that produces the same `AggregateReport` every time

    Useful for duplicate report testing

    Config:
        `report: dict[str, Any]`: static report to use instead of the default one.
    """

    config: ReportConfig

    _report = {"a": 1}

    def make_report(self) -> AggregateReport:
        if (report := self.config.report) is None:
            report = self._report
        return AggregateReport(deepcopy(report))


class RandomAggregateReportGenerator(UtilitySource):
    """Source that produces random `AggregateReport`s

    Useful for testing.

    Note: reports are randomly generates which means that although unlikely it is
    possible that duplicate reports will be generated.
    """

    def make_report(self) -> AggregateReport:
        data = {"a": 1}
        return AggregateReport(data)


class MalformedAggregateReportGenerator(UtilitySource):
    """Source that produces malformed `AggregateReport`s

    Useful for testing.
    """

    def make_report(self) -> AggregateReport:
        data = {"a": 1}
        return AggregateReport(data)


# Forensic Reports
# ..............................................................................
class StaticForensicReportGenerator(UtilitySource):
    """Source that produces the same `ForensicReport` every time

    Useful for duplicate report testing

    Config:
        `report: dict[str, Any]`: static report to use instead of the default one.
    """

    config: ReportConfig

    _report = {"a": 1}

    def make_report(self) -> ForensicReport:
        if (report := self.config.report) is None:
            report = self._report
        return ForensicReport(deepcopy(report))


class RandomForensicReportGenerator(UtilitySource):
    """Source that produces random `ForensicReport`s

    Useful for testing.

    Note: reports are randomly generates which means that although unlikely it is
    possible that duplicate reports will be generated.
    """

    def make_report(self) -> ForensicReport:
        data = {"a": 1}
        return ForensicReport(data)


class MalformedForensicReportGenerator(UtilitySource):
    """Source that produces malformed `ForensicReport`s

    Useful for testing.
    """

    def make_report(self) -> ForensicReport:
        data = {"a": 1}
        return ForensicReport(data)
