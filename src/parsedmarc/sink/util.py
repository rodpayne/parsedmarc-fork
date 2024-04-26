### IMPORTS
### ============================================================================
# Future
from __future__ import annotations

# Standard Library
import sys
from typing import Literal

# Installed
import orjson

# Local
from ..const import AppState
from ..report import Report
from .base import BaseConfig, Sink


### CLASSES
### ============================================================================
class Console(Sink):
    """Sink that writes reports to the console"""

    config: ConsoleConfig

    def setup(self) -> None:
        if self._state != AppState.SHUTDOWN:
            raise RuntimeError("Sink is already running")

        self._state = AppState.SETTING_UP

        try:
            if self.config.stream == "stdout":
                self.output = sys.stdout
            elif self.config.stream == "stderr":
                self.output = sys.stderr
            else:
                raise ValueError(f"Unsupport output stream: {self.config.stream}")

        except:
            self._state = AppState.SETUP_ERROR
            raise

        self._state = AppState.RUNNING
        return

    def cleanup(self) -> None:
        self.output.flush()
        return

    def process_report(self, report: Report) -> None:
        opts = 0
        if self.config.pretty:
            opts |= orjson.OPT_INDENT_2
        if self.config.sort:
            opts |= orjson.OPT_SORT_KEYS
        print(str(orjson.dumps(report.data, option=opts)), file=self.output)
        return


class ConsoleConfig(BaseConfig):
    stream: Literal["stdout", "stderr"] = "stdout"
    pretty: bool = False
    sort: bool = False
