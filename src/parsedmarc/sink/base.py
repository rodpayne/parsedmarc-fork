### IMPORTS
### ============================================================================
# Future
from __future__ import annotations

# Standard Library
import logging
from typing import Any, get_type_hints

# Installed
from pillar.logging import LoggingMixin, get_logger_name_for_instance
from pydantic import BaseModel

# Local
from ..const import AppState
from ..report import AggregateReport, ForensicReport, Report


### CLASSES
### ============================================================================
class Sink(LoggingMixin):
    """Base class for Sinks. Sinks receive reports for processing.

    *New in 9.0*.
    """

    config: BaseConfig

    def __init__(
        self,
        name: str = "default",
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Args:
            name: profile name for this instance, ideally should be unqiue to easily
                idenfity this instance and any log messages it produces
            config: config for this instance
        """
        self.name: str = name
        self._raw_config = config or {}
        self.logger = logging.getLogger(f"{get_logger_name_for_instance(self)}.i-{name}")

        config_class = get_type_hints(self.__class__)["config"]
        self.config = config_class(**config)

        self._state: AppState = AppState.SHUTDOWN

        self.validate_config()
        return

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"

    def __str__(self) -> str:
        return repr(self)

    @property
    def state(self) -> AppState:
        """Read only Sink state"""
        return self._state

    def validate_config(self) -> None:
        """Validate the config of this instance

        Child classes can override this method to implement their own logic.
        It is still recomended to call `super().validate_config()`.
        """
        return

    def setup(self) -> None:
        """Perform setup actions to ensure this Sink is ready to produce.

        Child classes can override this method to implement their own logic.

        Child classes should:
          - check that `self._state == AppState.SHUTDOWN`
          - set `self._state = AppState.SETTING_UP`
          - do their setup actions
          - if an error occurs set `self._state = AppState.SETUP_ERROR`
          - otherwise set `self._state = AppState.RUNNING`
        """
        if self._state != AppState.SHUTDOWN:
            raise RuntimeError("Sink is already running")
        self._state = AppState.RUNNING
        return

    def cleanup(self) -> None:
        """Perform cleanup on this source.

        This method is called as a part of `self.shutdown`.

        Child classes can override this method to implement their own logic.
        It is still recomended to call `super().cleanup()`.
        """
        if self._state != AppState.SHUTTING_DOWN:
            raise RuntimeError("Sink is not shutting_down")
        return

    def shutdown(self, timeout: int | float = 120, force: bool = False) -> None:
        """Attempt to gracefully shutdown this source.

        Args:
            timeout: Giveup after this many seonds (TODO)
            force: If a timeout would occur, instead force shutdown.
        """
        # pylint: disable=unused-argument

        if self._state != AppState.RUNNING:
            raise RuntimeError("Sink is not running")

        self._state = AppState.SHUTTING_DOWN

        # TODO: Timeout - consider using stopit package

        try:
            self.cleanup()
        except Exception:
            self._state = AppState.SHUTDOWN_ERROR
            raise

        self._state = AppState.SHUTDOWN
        return

    ## Reports
    ## -------------------------------------------------------------------------
    def process_report(self, report: Report) -> None:
        if self._state != AppState.RUNNING:
            raise RuntimeError("sink is not running")
        if isinstance(report, AggregateReport) and hasattr(self, "process_aggregate_report"):
            getattr(self, "process_aggregate_report")(report)
        elif isinstance(report, ForensicReport) and hasattr(self, "process_forensic_report"):
            getattr(self, "process_forensic_report")(report)
        else:
            raise NotImplementedError(f"Unsupported report type: {report}")
        return


class BaseConfig(BaseModel):
    pass
