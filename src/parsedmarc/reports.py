### IMPORTS
### ============================================================================
# Future
from __future__ import annotations

# Standard Library
from copy import deepcopy
from typing import Any

# Installed


### CLASSES
### ============================================================================
## Reports
## -----------------------------------------------------------------------------
class Report:
    """Base class for all reports"""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        return


class AggregateReport(Report):
    """A DMARC Aggregate Report"""

    CSV_FIELDS = [
        "xml_schema",
        "org_name",
        "org_email",
        "org_extra_contact_info",
        "report_id",
        "begin_date",
        "end_date",
        "errors",
        "domain",
        "adkim",
        "aspf",
        "p",
        "sp",
        "pct",
        "fo",
        "source_ip_address",
        "source_country",
        "source_reverse_dns",
        "source_base_domain",
        "count",
        "spf_aligned",
        "dkim_aligned",
        "dmarc_aligned",
        "disposition",
        "policy_override_reasons",
        "policy_override_comments",
        "envelope_from",
        "header_from",
        "envelope_to",
        "dkim_domains",
        "dkim_selectors",
        "dkim_results",
        "spf_domains",
        "spf_scopes",
        "spf_results",
    ]

    def to_csv_rows(self) -> list[dict[str, Any]]:
        """Convert this Aggregate report into a CSV compatible row

        Returns:
            rows as a dicts
        """

        def to_str(obj) -> str:
            return str(obj).lower()

        report_dict: dict[str, Any] = {
            "xml_schema": self.data["xml_schema"],
            "org_name": self.data["report_metadata"]["org_name"],
            "org_email": self.data["report_metadata"]["org_email"],
            "org_extra_contact_info": self.data["report_metadata"]["org_extra_contact_info"],
            "report_id": self.data["report_metadata"]["report_id"],
            "begin_date": self.data["report_metadata"]["begin_date"],
            "end_date": self.data["report_metadata"]["end_date"],
            "errors": "|".join(self.data["report_metadata"]["errors"]),
            "domain": self.data["policy_published"]["domain"],
            "adkim": self.data["policy_published"]["adkim"],
            "aspf": self.data["policy_published"]["aspf"],
            "p": self.data["policy_published"]["p"],
            "sp": self.data["policy_published"]["sp"],
            "pct": self.data["policy_published"]["pct"],
            "fo": self.data["policy_published"]["fo"],
        }

        rows: list[dict[str, Any]] = []

        for record in self.data["records"]:
            row = report_dict.copy()
            row["source_ip_address"] = record["source"]["ip_address"]
            row["source_country"] = record["source"]["country"]
            row["source_reverse_dns"] = record["source"]["reverse_dns"]
            row["source_base_domain"] = record["source"]["base_domain"]
            row["count"] = record["count"]
            row["spf_aligned"] = record["alignment"]["spf"]
            row["dkim_aligned"] = record["alignment"]["dkim"]
            row["dmarc_aligned"] = record["alignment"]["dmarc"]
            row["disposition"] = record["policy_evaluated"]["disposition"]
            policy_override_reasons = list(
                map(
                    lambda r_: r_["type"],
                    record["policy_evaluated"]["policy_override_reasons"],
                )
            )
            policy_override_comments = list(
                map(
                    lambda r_: r_["comment"] or "none",
                    record["policy_evaluated"]["policy_override_reasons"],
                )
            )
            row["policy_override_reasons"] = ",".join(policy_override_reasons)
            row["policy_override_comments"] = "|".join(policy_override_comments)
            row["envelope_from"] = record["identifiers"]["envelope_from"]
            row["header_from"] = record["identifiers"]["header_from"]
            row["envelope_to"] = record["identifiers"]["envelope_to"]
            dkim_domains = []
            dkim_selectors = []
            dkim_results = []
            for dkim_result in record["auth_results"]["dkim"]:
                dkim_domains.append(dkim_result["domain"])
                if "selector" in dkim_result:
                    dkim_selectors.append(dkim_result["selector"])
                dkim_results.append(dkim_result["result"])
            row["dkim_domains"] = ",".join(map(to_str, dkim_domains))
            row["dkim_selectors"] = ",".join(map(to_str, dkim_selectors))
            row["dkim_results"] = ",".join(map(to_str, dkim_results))
            spf_domains = []
            spf_scopes = []
            spf_results = []
            for spf_result in record["auth_results"]["spf"]:
                spf_domains.append(spf_result["domain"])
                spf_scopes.append(spf_result["scope"])
                spf_results.append(spf_result["result"])
            row["spf_domains"] = ",".join(map(to_str, spf_domains))
            row["spf_scopes"] = ",".join(map(to_str, spf_scopes))
            row["spf_results"] = ",".join(map(to_str, spf_results))
            rows.append(row)

        return rows


class ForensicReport(Report):
    """A DMARC Forensic Report"""

    CSV_FIELDS = [
        "feedback_type",
        "user_agent",
        "version",
        "original_envelope_id",
        "original_mail_from",
        "original_rcpt_to",
        "arrival_date",
        "arrival_date_utc",
        "subject",
        "message_id",
        "authentication_results",
        "dkim_domain",
        "source_ip_address",
        "source_country",
        "source_reverse_dns",
        "source_base_domain",
        "delivery_result",
        "auth_failure",
        "reported_domain",
        "authentication_mechanisms",
        "sample_headers_only",
    ]

    def to_csv_row(self) -> dict[str, Any]:
        """Convert this Forensic report into a CSV compatible row

        Returns:
            row as a dict
        """
        row = self.data.copy()
        row["source_ip_address"] = self.data["source"]["ip_address"]
        row["source_reverse_dns"] = self.data["source"]["reverse_dns"]
        row["source_base_domain"] = self.data["source"]["base_domain"]
        row["source_country"] = self.data["source"]["country"]
        del row["source"]
        row["subject"] = self.data["parsed_sample"]["subject"]
        row["auth_failure"] = ",".join(self.data["auth_failure"])
        row["authentication_mechanisms"] = ",".join(self.data["authentication_mechanisms"])
        del row["sample"]
        del row["parsed_sample"]
        return row


## Containers
## -----------------------------------------------------------------------------
class SortedReportContainer:
    def __init__(
        self,
        existing_aggregate_reports: list[AggregateReport] | None = None,
        existing_forensic_reports: list[ForensicReport] | None = None,
    ) -> None:
        self.aggregate_reports: list[AggregateReport] = existing_aggregate_reports or []
        self.forensic_reports: list[ForensicReport] = existing_forensic_reports or []
        return

    def add_report(self, report: Report) -> str:
        """Add a report to this container returning the added type.

        Args:
            report: the report to add

        Returns:
            the type of report added
        """
        if isinstance(report, AggregateReport):
            self.aggregate_reports.append(report)
            return "aggregate"

        if isinstance(report, ForensicReport):
            self.forensic_reports.append(report)
            return "forensic"

        raise ValueError(f"Unsupported report type: {type(report)}")

    def dict(self) -> dict[str, list]:
        dict_ = {
            "aggregate_reports": [deepcopy(report.data) for report in self.aggregate_reports],
            "forensic_reports": [deepcopy(report.data) for report in self.forensic_reports],
        }
        return dict_
