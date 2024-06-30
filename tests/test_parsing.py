### IMPORTS
### ============================================================================
# Future
from __future__ import annotations

# Standard Library
from glob import glob
import os

# Installed
import pytest

# Package
import parsedmarc


### SETUP
### ============================================================================
def get_files(glob_path) -> list[str]:
    """Get files matching glob given glob pattern"""
    return [path for path in glob(glob_path) if os.path.isfile(path)]


### TESTS
### ============================================================================
def test_parse_invalid():
    with pytest.raises(parsedmarc.InvalidDMARCReport):
        parsedmarc.parse_report_file("samples/empty.xml")
    return


@pytest.mark.parametrize("path", get_files("samples/aggregate/*"))
def test_parse_dmarc_aggregate(path: str):
    report = parsedmarc.parse_report_file(path)
    assert isinstance(report, parsedmarc.AggregateReport)

    # Convert to CSV to ensure is valid report
    parsedmarc.parsed_aggregate_reports_to_csv(report)
    return


@pytest.mark.parametrize("path", get_files("samples/forensic/*.eml"))
def test_parse_dmarc_forensic(path: str):
    report = parsedmarc.parse_report_file(path)
    assert isinstance(report, parsedmarc.ForensicReport)

    # Convert to CSV to ensure is valid report
    parsedmarc.parsed_forensic_reports_to_csv(report)
    return
