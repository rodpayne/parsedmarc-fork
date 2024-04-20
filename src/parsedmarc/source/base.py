### IMPORTS
### ============================================================================
# Future
from __future__ import annotations

# Standard Library
import enum
import logging
import types
from typing import Any, get_type_hints

# Installed
import dataclassy
from pillar.logging import LoggingMixin, get_logger_name_for_instance
from pydantic import BaseModel

# Local
from ..parser import ReportParser
from ..report import Report


### CONSTANTS
### ============================================================================
class JobStatus(enum.Enum):
    SUCCESS = enum.auto()
    ERROR = enum.auto()
    CANCELLED = enum.auto()


class SourceState(enum.Enum):
    SHUTDOWN = enum.auto()
    RUNNING = enum.auto()
    SHUTTING_DOWN = enum.auto()
    SHUTDOWN_ERROR = enum.auto()
    SETTING_UP = enum.auto()
    SETUP_ERROR = enum.auto()


### CLASSES
### ============================================================================
class Source(LoggingMixin):
    """Base class for all Sources. Sources generate reports to be consumed by other classes.

    *New in 9.0*.
    """

    config: BaseConfig

    def __init__(
        self,
        name: str = "default",
        parser: ReportParser | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Args:
            name: profile name for this instance, ideally should be unqiue to easily
                idenfity this instance and any log messages it produces
            parser: parser to use when generating reports
            config: config for this instance
        """
        self.name: str = name
        self.parser: ReportParser = parser or ReportParser()
        self._raw_config = config or {}
        self.logger = logging.getLogger(f"{get_logger_name_for_instance(self)}.i-{name}")

        config_class = get_type_hints(self.__class__)["config"]
        self.config = config_class(**config)

        self._state: SourceState = SourceState.SHUTDOWN

        self._outstanding_jobs: dict[str, Job] = {}

        self.validate_config()
        return

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"

    def __str__(self) -> str:
        return repr(self)

    @property
    def state(self) -> SourceState:
        """Read only Source state"""
        return self._state

    @property
    def outstanding_jobs(self) -> types.MappingProxyType[str, Job]:
        """Read only view of outstanding jobs"""
        return types.MappingProxyType(self._outstanding_jobs)

    def validate_config(self) -> None:
        """Validate the config of this instance

        Child classes can override this method to implement their own logic.
        It is still recomended to call `super().validate_config()`.
        """
        return

    def setup(self) -> None:
        """Perform setup actions to ensure this Source is ready to produce.

        Child classes can override this method to implement their own logic.

        Child classes should:
          - check that `self._state == SourceState.SHUTDOWN`
          - set `self._state = SourceState.SETTING_UP`
          - do their setup actions
          - if an error occurs set `self._state = SourceState.SETUP_ERROR`
          - otherwise set `self._state = SourceState.RUNNING`
        """
        if self._state != SourceState.SHUTDOWN:
            raise RuntimeError("Source is already running")
        self._state = SourceState.RUNNING
        return

    def cleanup(self) -> None:
        """Perform cleanup on this source.

        This method is called as a part of `self.shutdown`.

        Child classes can override this method to implement their own logic.
        It is still recomended to call `super().cleanup()`.
        """
        if self._state != SourceState.SHUTTING_DOWN:
            raise RuntimeError("Source is not shutting_down")
        return

    def shutdown(self, timeout: int | float = 120, force: bool = False) -> None:
        """Attempt to gracefully shutdown this source.

        Args:
            timeout: Giveup after this many seonds (TODO)
            force: If a timeout would occur, instead force shutdown.
        """
        # pylint: disable=unused-argument
        # timeout, force known unused.

        if self._state != SourceState.RUNNING:
            raise RuntimeError("Source is not running")

        self._state = SourceState.SHUTTING_DOWN

        # TODO: Timeout - consider using stopit package

        try:
            for job in list(self._outstanding_jobs.values()):
                self.debug("Cancelling job: {job.identifier}")
                self.ack_job(job, JobStatus.CANCELLED)

            self.debug("Finished cancelling jobs, cleaning up")
            self.cleanup()
        except Exception:
            self._state = SourceState.SHUTDOWN_ERROR
            raise

        self._state = SourceState.SHUTDOWN
        return

    ## Jobs Mode
    ## -------------------------------------------------------------------------
    def get_job(self) -> Job | None:
        """Get the next job for this Source

        Child classes MUST implement this method.

        Child classes must call `self.register_job(job)` before returning.

        If no `Job` is available, child classes should return `None` rather than blocking indefinintely.

        Returns:
            The job if one is available, else `None`.
        """
        raise NotImplementedError()

    def register_job(self, job: Job) -> None:
        """Register a job to this source so we can keep track of it

        Args:
            job: the job to register
        """
        if self._state != SourceState.RUNNING:
            raise RuntimeError("Source is not running")

        if job.identifier in self._outstanding_jobs:
            raise RuntimeError(f"Duplicate job {job.identifier}")

        self.debug(f"Registered job: {job.identifier}")
        self._outstanding_jobs[job.identifier] = job
        return

    def ack_job(self, job: Job, status: JobStatus) -> None:
        """Acknowledge a completed job

        Child classes should override this method to implement their own logic.

        Child classes MUST still call `super().ack_job(job, status)`.

        Args:
            job: the job to acknowledge
            status: indicates how the job was processed
        """
        if self._state != SourceState.RUNNING:
            raise RuntimeError("Source is not running")

        self.debug(f"Acknowledged job: {job.identifier} ({status})")
        del self._outstanding_jobs[job.identifier]
        return

    ## Bulk Mode
    ## -------------------------------------------------------------------------


class BaseConfig(BaseModel):  # pylint: disable=too-few-public-methods
    pass


## ReportJob
## -----------------------------------------------------------------------------
@dataclassy.dataclass(slots=True)
class Job:  # pylint: disable=too-few-public-methods
    """Container for a report and the source it came from.

    This allows for callbacks / tracking the report as it is processed

    Attributes:
        source: Source that produced this job
        report:
        identifier: identifier for this job, it should be unique for all jobs
            generated by the source.
        data: extra data specific to the source.

    *New in 9.0*.
    """

    source: Source
    report: Report
    identifier: str
    data: dict[str, Any] = dataclassy.factory(dict)
