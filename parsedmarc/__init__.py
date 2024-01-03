"""A Python package for parsing DMARC reports"""

# Standard Library
from base64 import b64decode
import binascii
from collections import OrderedDict
from csv import DictWriter
from datetime import datetime
import email
import email.utils
from io import BytesIO, StringIO
import json
import mailbox
import os
import re
import shutil
import tempfile
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Union, cast
import xml.parsers.expat as expat
import zipfile
import zlib

# Installed
from expiringdict import ExpiringDict
from lxml import etree
import mailparser
from mailsuite.smtp import send_email
import xmltodict

# Package
from parsedmarc.log import logger
from parsedmarc.mail import MailboxConnection
from parsedmarc.utils import (
    convert_outlook_msg,
    get_base_domain,
    get_ip_address_info,
    human_timestamp_to_datetime,
    is_outlook_msg,
    parse_email,
    timestamp_to_human,
)

__version__ = "8.6.4"

logger.debug(f"parsedmarc v{__version__}")

feedback_report_regex = re.compile(r"^([\w\-]+): (.+)$", re.MULTILINE)
xml_header_regex = re.compile(r"^<\?xml .*?>", re.MULTILINE)
xml_schema_regex = re.compile(r"</??xs:schema.*>", re.MULTILINE)
text_report_regex = re.compile(r"\s*([a-zA-Z\s]+):\s(.+)", re.MULTILINE)

MAGIC_ZIP = b"\x50\x4B\x03\x04"
MAGIC_GZIP = b"\x1F\x8B"
MAGIC_XML = b"\x3c\x3f\x78\x6d\x6c\x20"

IP_ADDRESS_CACHE = ExpiringDict(max_len=10000, max_age_seconds=1800)


class ParserError(RuntimeError):
    """Raised whenever the parser fails for some reason"""


class InvalidDMARCReport(ParserError):
    """Raised when an invalid DMARC report is encountered"""


class InvalidAggregateReport(InvalidDMARCReport):
    """Raised when an invalid DMARC aggregate report is encountered"""


class InvalidForensicReport(InvalidDMARCReport):
    """Raised when an invalid DMARC forensic report is encountered"""


def _parse_report_record(
    record: OrderedDict,
    ip_db_path: Optional[str] = None,
    offline: bool = False,
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 2.0,
    parallel: bool = False,
) -> OrderedDict:
    """Convert a record from a DMARC aggregate report into a more consistent format

    Args:
        record: The record to convert
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        offline: Do not query online for geolocation or DNS
        nameservers: A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout: Sets the DNS timeout in seconds

    Returns:
        The converted record
    """
    record = record.copy()
    new_record: OrderedDict[str, Any] = OrderedDict()
    new_record_source = get_ip_address_info(
        record["row"]["source_ip"],
        cache=IP_ADDRESS_CACHE,
        ip_db_path=ip_db_path,
        offline=offline,
        nameservers=nameservers,
        timeout=dns_timeout,
        parallel=parallel,
    )
    new_record["source"] = new_record_source
    new_record["count"] = int(record["row"]["count"])
    policy_evaluated = record["row"]["policy_evaluated"].copy()
    new_policy_evaluated = OrderedDict(
        [
            ("disposition", "none"),
            ("dkim", "fail"),
            ("spf", "fail"),
            ("policy_override_reasons", []),
        ]
    )
    if "disposition" in policy_evaluated:
        new_policy_evaluated["disposition"] = policy_evaluated["disposition"]
        if cast(str, new_policy_evaluated["disposition"]).strip().lower() == "pass":
            new_policy_evaluated["disposition"] = "none"
    if "dkim" in policy_evaluated:
        new_policy_evaluated["dkim"] = policy_evaluated["dkim"]
    if "spf" in policy_evaluated:
        new_policy_evaluated["spf"] = policy_evaluated["spf"]
    reasons = []
    spf_aligned = policy_evaluated["spf"] is not None and policy_evaluated["spf"].lower() == "pass"
    dkim_aligned = (
        policy_evaluated["dkim"] is not None and policy_evaluated["dkim"].lower() == "pass"
    )
    dmarc_aligned = spf_aligned or dkim_aligned
    new_record["alignment"] = dict()
    new_record["alignment"]["spf"] = spf_aligned
    new_record["alignment"]["dkim"] = dkim_aligned
    new_record["alignment"]["dmarc"] = dmarc_aligned
    if "reason" in policy_evaluated:
        if type(policy_evaluated["reason"]) is list:
            reasons = policy_evaluated["reason"]
        else:
            reasons = [policy_evaluated["reason"]]
    for reason in reasons:
        if "comment" not in reason:
            reason["comment"] = None
    new_policy_evaluated["policy_override_reasons"] = reasons
    new_record["policy_evaluated"] = new_policy_evaluated
    if "identities" in record:
        new_record["identifiers"] = record["identities"].copy()
    else:
        new_record["identifiers"] = record["identifiers"].copy()
    new_record["auth_results"] = OrderedDict([("dkim", []), ("spf", [])])
    if type(new_record["identifiers"]["header_from"]) is str:
        lowered_from = new_record["identifiers"]["header_from"].lower()
    else:
        lowered_from = ""
    new_record["identifiers"]["header_from"] = lowered_from
    if record["auth_results"] is not None:
        auth_results = record["auth_results"].copy()
        if "spf" not in auth_results:
            auth_results["spf"] = []
        if "dkim" not in auth_results:
            auth_results["dkim"] = []
    else:
        auth_results = new_record["auth_results"].copy()

    if not isinstance(auth_results["dkim"], list):
        auth_results["dkim"] = [auth_results["dkim"]]
    for result in auth_results["dkim"]:
        if "domain" in result and result["domain"] is not None:
            new_result = OrderedDict([("domain", result["domain"])])
            if "selector" in result and result["selector"] is not None:
                new_result["selector"] = result["selector"]
            else:
                new_result["selector"] = "none"
            if "result" in result and result["result"] is not None:
                new_result["result"] = result["result"]
            else:
                new_result["result"] = "none"
            new_record["auth_results"]["dkim"].append(new_result)

    if not isinstance(auth_results["spf"], list):
        auth_results["spf"] = [auth_results["spf"]]
    for result in auth_results["spf"]:
        if "domain" in result and result["domain"] is not None:
            new_result = OrderedDict([("domain", result["domain"])])
            if "scope" in result and result["scope"] is not None:
                new_result["scope"] = result["scope"]
            else:
                new_result["scope"] = "mfrom"
            if "result" in result and result["result"] is not None:
                new_result["result"] = result["result"]
            else:
                new_result["result"] = "none"
            new_record["auth_results"]["spf"].append(new_result)

    if "envelope_from" not in new_record["identifiers"]:
        envelope_from = None
        if len(auth_results["spf"]) > 0:
            spf_result = auth_results["spf"][-1]
            if "domain" in spf_result:
                envelope_from = spf_result["domain"]
        if envelope_from is not None:
            envelope_from = str(envelope_from).lower()
        new_record["identifiers"]["envelope_from"] = envelope_from

    elif new_record["identifiers"]["envelope_from"] is None:
        if len(auth_results["spf"]) > 0:
            envelope_from = new_record["auth_results"]["spf"][-1]["domain"]
            if envelope_from is not None:
                envelope_from = str(envelope_from).lower()
            new_record["identifiers"]["envelope_from"] = envelope_from

    envelope_to = None
    if "envelope_to" in new_record["identifiers"]:
        envelope_to = new_record["identifiers"]["envelope_to"]
        del new_record["identifiers"]["envelope_to"]

    new_record["identifiers"]["envelope_to"] = envelope_to

    return new_record


def parse_aggregate_report_xml(
    xml: str,
    ip_db_path: Optional[str] = None,
    offline: bool = False,
    nameservers: Optional[List[str]] = None,
    timeout: float = 2.0,
    parallel: bool = False,
    keep_alive: Optional[Callable] = None,
) -> OrderedDict[str, Any]:
    """Parses a DMARC XML report string and returns a consistent OrderedDict

    Args:
        xml: A string of DMARC aggregate report XML
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        offline: Do not query online for geolocation or DNS
        nameservers: A list of one or more nameservers to use (Cloudflare's public DNS resolvers by default)
        timeout: Sets the DNS timeout in seconds
        parallel: Parallel processing
        keep_alive: Keep alive function

    Returns:
        The parsed aggregate DMARC report
    """
    errors = []
    # Parse XML and recover from errors
    try:
        xmltodict.parse(xml)["feedback"]
    except Exception as e:
        errors.append(f"Invalid XML: {e!r}")
        try:
            tree = etree.parse(
                BytesIO(xml.encode("utf-8")), etree.XMLParser(recover=True, resolve_entities=False)
            )
            s = etree.tostring(tree)
            xml = "" if s is None else s.decode("utf-8")
        except Exception:
            xml = "<a/>"

    try:
        # Replace XML header (sometimes they are invalid)
        xml = xml_header_regex.sub('<?xml version="1.0"?>', xml)

        # Remove invalid schema tags
        xml = xml_schema_regex.sub("", xml)

        report = xmltodict.parse(xml)["feedback"]
        report_metadata = report["report_metadata"]
        schema = "draft"
        if "version" in report:
            schema = report["version"]
        new_report: OrderedDict[str, Any] = OrderedDict([("xml_schema", schema)])
        new_report_metadata: OrderedDict[str, Any] = OrderedDict()
        if report_metadata["org_name"] is None:
            if report_metadata["email"] is not None:
                report_metadata["org_name"] = report_metadata["email"].split("@")[-1]
        org_name = report_metadata["org_name"]
        if org_name is not None and " " not in org_name:
            new_org_name = get_base_domain(org_name)
            if new_org_name is not None:
                org_name = new_org_name
        if not org_name:
            logger.debug(f"Could not parse org_name from XML.\r\n{report}")
            raise KeyError(
                "Organization name is missing. This field is a requirement for saving the report"
            )
        new_report_metadata["org_name"] = org_name
        new_report_metadata["org_email"] = report_metadata["email"]
        extra = None
        if "extra_contact_info" in report_metadata:
            extra = report_metadata["extra_contact_info"]
        new_report_metadata["org_extra_contact_info"] = extra
        new_report_metadata["report_id"] = report_metadata["report_id"]
        report_id = new_report_metadata["report_id"]
        report_id = report_id.replace("<", "").replace(">", "").split("@")[0]
        new_report_metadata["report_id"] = report_id
        date_range = report["report_metadata"]["date_range"]
        if int(date_range["end"]) - int(date_range["begin"]) > 2 * 86400:
            _error = "Timespan > 24 hours - RFC 7489 section 7.2"
            errors.append(_error)
        date_range["begin"] = timestamp_to_human(date_range["begin"])
        date_range["end"] = timestamp_to_human(date_range["end"])
        new_report_metadata["begin_date"] = date_range["begin"]
        new_report_metadata["end_date"] = date_range["end"]
        if "error" in report["report_metadata"]:
            if not isinstance(report["report_metadata"]["error"], list):
                errors = [report["report_metadata"]["error"]]
            else:
                errors = report["report_metadata"]["error"]
        new_report_metadata["errors"] = errors
        new_report["report_metadata"] = new_report_metadata
        records = []
        policy_published = report["policy_published"]
        new_policy_published = OrderedDict()
        new_policy_published["domain"] = policy_published["domain"]
        adkim = "r"
        if "adkim" in policy_published:
            if policy_published["adkim"] is not None:
                adkim = policy_published["adkim"]
        new_policy_published["adkim"] = adkim
        aspf = "r"
        if "aspf" in policy_published:
            if policy_published["aspf"] is not None:
                aspf = policy_published["aspf"]
        new_policy_published["aspf"] = aspf
        new_policy_published["p"] = policy_published["p"]
        sp = new_policy_published["p"]
        if "sp" in policy_published:
            if policy_published["sp"] is not None:
                sp = report["policy_published"]["sp"]
        new_policy_published["sp"] = sp
        pct = "100"
        if "pct" in policy_published:
            if policy_published["pct"] is not None:
                pct = report["policy_published"]["pct"]
        new_policy_published["pct"] = pct
        fo = "0"
        if "fo" in policy_published:
            if policy_published["fo"] is not None:
                fo = report["policy_published"]["fo"]
        new_policy_published["fo"] = fo
        new_report["policy_published"] = new_policy_published

        if type(report["record"]) is list:
            record_count = len(report["record"])
            for i in range(record_count):
                if keep_alive is not None and i > 0 and i % 20 == 0:
                    logger.debug("Sending keepalive cmd")
                    keep_alive()
                    logger.debug(f"Processed {i}/{record_count}")
                report_record = _parse_report_record(
                    report["record"][i],
                    ip_db_path=ip_db_path,
                    offline=offline,
                    nameservers=nameservers,
                    dns_timeout=timeout,
                    parallel=parallel,
                )
                records.append(report_record)

        else:
            report_record = _parse_report_record(
                report["record"],
                ip_db_path=ip_db_path,
                offline=offline,
                nameservers=nameservers,
                dns_timeout=timeout,
                parallel=parallel,
            )
            records.append(report_record)

        new_report["records"] = records

        return new_report

    except expat.ExpatError as error:
        raise InvalidAggregateReport(f"Invalid XML: {error!r}")

    except KeyError as error:
        raise InvalidAggregateReport(f"Missing field: {error!r}")
    except AttributeError:
        raise InvalidAggregateReport("Report missing required section")

    except Exception as error:
        raise InvalidAggregateReport(f"Unexpected error: {error!r}")


def extract_xml(input_: Union[str, bytes, BinaryIO]) -> str:
    """Extracts xml from a zip or gzip file at the given path, file-like object, or bytes.

    Args:
        input_: A path to a file, a file like object, or bytes

    Returns:
        The extracted XML
    """
    file_object: BinaryIO
    try:
        if isinstance(input_, str):
            file_object = open(input_, "rb")
        elif isinstance(input_, bytes):
            file_object = BytesIO(input_)
        else:
            file_object = input_

        header = file_object.read(6)
        file_object.seek(0)

        if header.startswith(MAGIC_ZIP):
            _zip = zipfile.ZipFile(file_object)
            xml = _zip.open(_zip.namelist()[0]).read().decode(errors="ignore")

        elif header.startswith(MAGIC_GZIP):
            xml = zlib.decompress(file_object.read(), zlib.MAX_WBITS | 16).decode(errors="ignore")

        elif header.startswith(MAGIC_XML):
            xml = file_object.read().decode(errors="ignore")

        else:
            file_object.close()
            raise InvalidAggregateReport("Not a valid zip, gzip, or xml file")

        file_object.close()

    except FileNotFoundError:
        raise InvalidAggregateReport("File was not found")
    except UnicodeDecodeError:
        file_object.close()
        raise InvalidAggregateReport("File objects must be opened in binary " "(rb) mode")
    except Exception as error:
        file_object.close()
        raise InvalidAggregateReport(f"Invalid archive file: {error!r}")

    return xml


def parse_aggregate_report_file(
    _input: Union[bytes, str, BinaryIO],
    offline: bool = False,
    ip_db_path: Optional[str] = None,
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 2.0,
    parallel: bool = False,
    keep_alive: Optional[Callable] = None,
) -> OrderedDict[str, Any]:
    """Parse a file at the given path, a file-like object. or bytes as an aggregate DMARC report

    Args:
        _input: A path to a file, a file like object, or bytes
        offline: Do not query online for geolocation or DNS
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        nameservers: A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        dns_timeout: Sets the DNS timeout in seconds
        parallel: Parallel processing
        keep_alive: Keep alive function

    Returns:
        The parsed DMARC aggregate report
    """
    xml = extract_xml(_input)

    return parse_aggregate_report_xml(
        xml,
        ip_db_path=ip_db_path,
        offline=offline,
        nameservers=nameservers,
        timeout=dns_timeout,
        parallel=parallel,
        keep_alive=keep_alive,
    )


def parsed_aggregate_reports_to_csv_rows(
    reports: Union[OrderedDict, List[OrderedDict]]
) -> List[Dict[str, Union[str, int, bool]]]:
    """Convert one or more parsed aggregate reports to list of dicts in flat CSV format

    Args:
        reports: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        Parsed aggregate report data as a list of dicts in flat CSV format
    """

    def to_str(obj):
        return str(obj).lower()

    if type(reports) is OrderedDict:
        reports = [reports]

    rows = []

    for report in reports:
        xml_schema = report["xml_schema"]
        org_name = report["report_metadata"]["org_name"]
        org_email = report["report_metadata"]["org_email"]
        org_extra_contact = report["report_metadata"]["org_extra_contact_info"]
        report_id = report["report_metadata"]["report_id"]
        begin_date = report["report_metadata"]["begin_date"]
        end_date = report["report_metadata"]["end_date"]
        errors = "|".join(report["report_metadata"]["errors"])
        domain = report["policy_published"]["domain"]
        adkim = report["policy_published"]["adkim"]
        aspf = report["policy_published"]["aspf"]
        p = report["policy_published"]["p"]
        sp = report["policy_published"]["sp"]
        pct = report["policy_published"]["pct"]
        fo = report["policy_published"]["fo"]

        report_dict = dict(
            xml_schema=xml_schema,
            org_name=org_name,
            org_email=org_email,
            org_extra_contact_info=org_extra_contact,
            report_id=report_id,
            begin_date=begin_date,
            end_date=end_date,
            errors=errors,
            domain=domain,
            adkim=adkim,
            aspf=aspf,
            p=p,
            sp=sp,
            pct=pct,
            fo=fo,
        )

        for record in report["records"]:
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
                map(lambda r_: r_["type"], record["policy_evaluated"]["policy_override_reasons"])
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
            envelope_to = record["identifiers"]["envelope_to"]
            row["envelope_to"] = envelope_to
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

    for r in rows:
        for k, v in r.items():
            if type(v) not in [str, int, bool]:
                r[k] = ""

    return rows


def parsed_aggregate_reports_to_csv(reports: Union[OrderedDict, List[OrderedDict]]) -> str:
    """Convert one or more parsed aggregate reports to flat CSV format, including headers

    Args:
        reports: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        Parsed aggregate report data in flat CSV format, including headers
    """

    fields = [
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

    csv_file_object = StringIO(newline="\n")
    writer = DictWriter(csv_file_object, fields)
    writer.writeheader()

    rows = parsed_aggregate_reports_to_csv_rows(reports)

    for row in rows:
        writer.writerow(row)
        csv_file_object.flush()

    return csv_file_object.getvalue()


def parse_forensic_report(
    feedback_report: str,
    sample: str,
    msg_date: datetime,
    offline: bool = False,
    ip_db_path: Optional[str] = None,
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 2.0,
    strip_attachment_payloads: bool = False,
    parallel: bool = False,
) -> OrderedDict:
    """Converts a DMARC forensic report and sample to a ``OrderedDict``

    Args:
        feedback_report: A message's feedback report as a string
        sample: The RFC 822 headers or RFC 822 message sample
        msg_date: The message's date header
        offline: Do not query online for geolocation or DNS
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        nameservers (list): A list of one or more nameservers to use (Cloudflare's public DNS resolvers by default)
        dns_timeout: Sets the DNS timeout in seconds
        strip_attachment_payloads: Remove attachment payloads from forensic report results
        parallel: Parallel processing

    Returns:
        A parsed report and sample
    """
    delivery_results = ["delivered", "spam", "policy", "reject", "other"]

    try:
        parsed_report = OrderedDict()
        report_values = feedback_report_regex.findall(feedback_report)
        for report_value in report_values:
            key = report_value[0].lower().replace("-", "_")
            parsed_report[key] = report_value[1]

        if "arrival_date" not in parsed_report:
            if msg_date is None:
                raise InvalidForensicReport("Forensic sample is not a valid email")
            parsed_report["arrival_date"] = msg_date.isoformat()

        if "version" not in parsed_report:
            parsed_report["version"] = None

        if "user_agent" not in parsed_report:
            parsed_report["user_agent"] = None

        if "delivery_result" not in parsed_report:
            parsed_report["delivery_result"] = None
        else:
            for delivery_result in delivery_results:
                if delivery_result in parsed_report["delivery_result"].lower():
                    parsed_report["delivery_result"] = delivery_result
                    break
        if parsed_report["delivery_result"] not in delivery_results:
            parsed_report["delivery_result"] = "other"

        parsed_report["arrival_date_utc"] = human_timestamp_to_datetime(
            parsed_report["arrival_date"], to_utc=True
        ).strftime("%Y-%m-%d %H:%M:%S")

        ip_address = re.split(r"\s", parsed_report["source_ip"]).pop(0)
        parsed_report_source = get_ip_address_info(
            ip_address,
            ip_db_path=ip_db_path,
            offline=offline,
            nameservers=nameservers,
            timeout=dns_timeout,
            parallel=parallel,
        )
        parsed_report["source"] = parsed_report_source
        del parsed_report["source_ip"]

        if "identity_alignment" not in parsed_report:
            parsed_report["authentication_mechanisms"] = []
        elif parsed_report["identity_alignment"] == "none":
            parsed_report["authentication_mechanisms"] = []
            del parsed_report["identity_alignment"]
        else:
            auth_mechanisms = parsed_report["identity_alignment"]
            auth_mechanisms = auth_mechanisms.split(",")
            parsed_report["authentication_mechanisms"] = auth_mechanisms
            del parsed_report["identity_alignment"]

        if "auth_failure" not in parsed_report:
            parsed_report["auth_failure"] = "dmarc"
        auth_failure = parsed_report["auth_failure"].split(",")
        parsed_report["auth_failure"] = auth_failure

        optional_fields = [
            "original_envelope_id",
            "dkim_domain",
            "original_mail_from",
            "original_rcpt_to",
        ]
        for optional_field in optional_fields:
            if optional_field not in parsed_report:
                parsed_report[optional_field] = None

        parsed_sample = parse_email(sample, strip_attachment_payloads=strip_attachment_payloads)

        if "reported_domain" not in parsed_report:
            parsed_report["reported_domain"] = parsed_sample["from"]["domain"]

        sample_headers_only = False
        number_of_attachments = len(parsed_sample["attachments"])
        if number_of_attachments < 1 and parsed_sample["body"] is None:
            sample_headers_only = True
        if sample_headers_only and parsed_sample["has_defects"]:
            del parsed_sample["defects"]
            del parsed_sample["defects_categories"]
            del parsed_sample["has_defects"]
        parsed_report["sample_headers_only"] = sample_headers_only
        parsed_report["sample"] = sample
        parsed_report["parsed_sample"] = parsed_sample

        return parsed_report

    except KeyError as error:
        raise InvalidForensicReport(f"Missing value: {error!r}")

    except Exception as error:
        raise InvalidForensicReport(f"Unexpected error: {error!r}")


def parsed_forensic_reports_to_csv_rows(
    reports: Union[OrderedDict, List[OrderedDict]]
) -> List[Dict[str, Any]]:
    """Convert one or more parsed forensic reports to a list of dicts in flat CSV format

    Args:
        reports: A parsed forensic report or list of parsed forensic reports

    Returns:
        Parsed forensic report data as a list of dicts in flat CSV format
    """
    if type(reports) is OrderedDict:
        reports = [reports]

    rows = []

    for report in reports:
        row = report.copy()
        row["source_ip_address"] = report["source"]["ip_address"]
        row["source_reverse_dns"] = report["source"]["reverse_dns"]
        row["source_base_domain"] = report["source"]["base_domain"]
        row["source_country"] = report["source"]["country"]
        del row["source"]
        row["subject"] = report["parsed_sample"]["subject"]
        row["auth_failure"] = ",".join(report["auth_failure"])
        authentication_mechanisms = report["authentication_mechanisms"]
        row["authentication_mechanisms"] = ",".join(authentication_mechanisms)
        del row["sample"]
        del row["parsed_sample"]
        rows.append(row)

    return rows


def parsed_forensic_reports_to_csv(reports: Union[OrderedDict, List[OrderedDict]]) -> str:
    """Convert one or more parsed forensic reports to flat CSV format, including headers

    Args:
        reports: A parsed forensic report or list of parsed forensic reports

    Returns:
        Parsed forensic report data in flat CSV format, including headers
    """
    fields = [
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

    csv_file = StringIO()
    csv_writer = DictWriter(csv_file, fieldnames=fields)
    csv_writer.writeheader()

    rows = parsed_forensic_reports_to_csv_rows(reports)

    for row in rows:
        new_row: Dict[str, Any] = {}
        for key in new_row.keys():
            new_row[key] = row[key]
        csv_writer.writerow(new_row)

    return csv_file.getvalue()


def parse_report_email(
    input_: Union[bytes, str],
    offline: bool = False,
    ip_db_path: Optional[str] = None,
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 2.0,
    strip_attachment_payloads: bool = False,
    parallel: bool = False,
    keep_alive: Optional[Callable] = None,
) -> OrderedDict[str, Union[str, OrderedDict]]:
    """Parse a DMARC report from an email

    Args:
        input_: An emailed DMARC report in RFC 822 format, as bytes or a string
        offline: Do not query online for geolocation on DNS
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        nameservers: A list of one or more nameservers to use
        dns_timeout: Sets the DNS timeout in seconds
        strip_attachment_payloads: Remove attachment payloads from forensic report results
        parallel: Parallel processing
        keep_alive: keep alive function

    Returns:
        Dictionary of `{"report_type": "aggregate" or "forensic", "report": report}`
    """
    try:
        if isinstance(input_, bytes) and is_outlook_msg(input_):
            input_ = convert_outlook_msg(input_)
        if isinstance(input_, bytes):
            input_ = input_.decode(encoding="utf8", errors="replace")
        msg = mailparser.parse_from_string(input_)
        msg_headers = json.loads(msg.headers_json)
        if "Date" in msg_headers:
            date = human_timestamp_to_datetime(msg_headers["Date"])
        else:
            date = datetime.utcnow()
        msg = email.message_from_string(input_)

    except Exception as e:
        raise InvalidDMARCReport(e.__str__())
    subject = None
    feedback_report = None
    sample = None
    if "From" in msg_headers:
        logger.info(f"Parsing mail from {msg_headers['From']}")
    if "Subject" in msg_headers:
        subject = msg_headers["Subject"]
    for part in msg.walk():
        content_type = part.get_content_type()
        payload = part.get_payload()
        if not isinstance(payload, list):
            payload = [payload]
        payload = payload[0].__str__()
        if content_type == "message/feedback-report":
            try:
                if "Feedback-Type" in payload:
                    feedback_report = payload
                else:
                    feedback_report = b64decode(payload).__str__()
                feedback_report = feedback_report.lstrip("b'").rstrip("'")
                feedback_report = feedback_report.replace("\\r", "")
                feedback_report = feedback_report.replace("\\n", "\n")
            except (ValueError, TypeError, binascii.Error):
                feedback_report = payload

        elif content_type == "text/rfc822-headers":
            sample = payload
        elif content_type == "message/rfc822":
            sample = payload
        elif content_type == "text/plain":
            if "A message claiming to be from you has failed" in payload:
                parts = payload.split("detected.")
                field_matches = text_report_regex.findall(parts[0])
                fields = dict()
                for match in field_matches:
                    field_name = match[0].lower().replace(" ", "-")
                    fields[field_name] = match[1].strip()
                feedback_report = f"Arrival-Date: {fields['received-date']}\nSource-IP: {fields['sender-ip-address']}"
                sample = parts[1].lstrip()
                sample = sample.replace("=\r\n", "")
                logger.debug(sample)
        else:
            try:
                payload = b64decode(payload)
                if (
                    payload.startswith(MAGIC_ZIP)
                    or payload.startswith(MAGIC_GZIP)
                    or payload.startswith(MAGIC_XML)
                ):
                    ns = nameservers
                    aggregate_report = parse_aggregate_report_file(
                        payload,
                        ip_db_path=ip_db_path,
                        offline=offline,
                        nameservers=ns,
                        dns_timeout=dns_timeout,
                        parallel=parallel,
                        keep_alive=keep_alive,
                    )
                    return OrderedDict([("report_type", "aggregate"), ("report", aggregate_report)])

            except (TypeError, ValueError, binascii.Error):
                pass

            except InvalidAggregateReport as e:
                error = (
                    f"Message with subject {subject!r} is not a valid aggregate DMARC report: {e!r}"
                )
                raise InvalidAggregateReport(error)

            except Exception as e:
                error = f"Unable to parse message with subject {subject!r}: {e!r}"
                raise InvalidDMARCReport(error)

    if feedback_report and sample:
        try:
            forensic_report = parse_forensic_report(
                feedback_report,
                sample,
                date,
                offline=offline,
                nameservers=nameservers,
                dns_timeout=dns_timeout,
                strip_attachment_payloads=strip_attachment_payloads,
                parallel=parallel,
            )
        except InvalidForensicReport as e:
            error = f"Message with subject {subject!r} is not a valid forensic DMARC report: {e!r}"
            raise InvalidForensicReport(error)
        except Exception as e:
            raise InvalidForensicReport(repr(e))

        return OrderedDict([("report_type", "forensic"), ("report", forensic_report)])

    error = f"Message with subject {subject!r} is not a valid DMARC report"
    raise InvalidDMARCReport(error)


def parse_report_file(
    input_: Union[str, bytes, BinaryIO],
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 2.0,
    strip_attachment_payloads: bool = False,
    ip_db_path: Optional[str] = None,
    offline: bool = False,
    parallel: bool = False,
    keep_alive: Optional[Callable] = None,
) -> OrderedDict:
    """Parse a DMARC aggregate or forensic file at the given path, a file-like object. or bytes

    Args:
        input_: A path to a file, a file like object, or bytes
        nameservers: A list of one or more nameservers to use (Cloudflare's public DNS resolvers by default)
        dns_timeout: Sets the DNS timeout in seconds
        strip_attachment_payloads: Remove attachment payloads from forensic report results
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        offline: Do not make online queries for geolocation or DNS
        parallel: Parallel processing
        keep_alive: Keep alive function

    Returns:
        The parsed DMARC report
    """
    file_object: BinaryIO
    if isinstance(input_, str):
        logger.debug(f"Parsing {input_}")
        file_object = open(input_, "rb")
    elif isinstance(input_, bytes):
        file_object = BytesIO(input_)
    else:
        file_object = input_

    content = file_object.read()
    file_object.close()

    results: OrderedDict[str, Union[str, OrderedDict]]
    try:
        report = parse_aggregate_report_file(
            content,
            ip_db_path=ip_db_path,
            offline=offline,
            nameservers=nameservers,
            dns_timeout=dns_timeout,
            parallel=parallel,
            keep_alive=keep_alive,
        )
        results = OrderedDict([("report_type", "aggregate"), ("report", report)])

    except InvalidAggregateReport:
        try:
            results = parse_report_email(
                content,
                ip_db_path=ip_db_path,
                offline=offline,
                nameservers=nameservers,
                dns_timeout=dns_timeout,
                strip_attachment_payloads=strip_attachment_payloads,
                parallel=parallel,
                keep_alive=keep_alive,
            )
        except InvalidDMARCReport:
            raise InvalidDMARCReport("Not a valid aggregate or forensic " "report")
    return results


def get_dmarc_reports_from_mbox(
    input_: str,
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 2.0,
    strip_attachment_payloads: bool = False,
    ip_db_path: Optional[str] = None,
    offline: bool = False,
    parallel: bool = False,
) -> OrderedDict[str, List[OrderedDict]]:
    """Parses a mailbox in mbox format containing e-mails with attached DMARC reports

    Args:
        input_: A path to a mbox file
        nameservers: A list of one or more nameservers to use (Cloudflare's public DNS resolvers by default)
        dns_timeout: Sets the DNS timeout in seconds
        strip_attachment_payloads: Remove attachment payloads from forensic report results
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        offline: Do not make online queries for geolocation or DNS
        parallel: Parallel processing

    Returns:
        Dictionary of Lists of ``aggregate_reports`` and ``forensic_reports``
    """
    aggregate_reports: List[OrderedDict] = []
    forensic_reports: List[OrderedDict] = []
    try:
        mbox = mailbox.mbox(input_)
        message_keys = mbox.keys()
        total_messages = len(message_keys)
        logger.debug(f"Found {total_messages} messages in {input_}")
        for i in range(len(message_keys)):
            message_key = message_keys[i]
            logger.info(f"Processing message {i+1} of {total_messages}")
            msg_content = mbox.get_string(message_key)
            try:
                sa = strip_attachment_payloads
                parsed_email = parse_report_email(
                    msg_content,
                    ip_db_path=ip_db_path,
                    offline=offline,
                    nameservers=nameservers,
                    dns_timeout=dns_timeout,
                    strip_attachment_payloads=sa,
                    parallel=parallel,
                )
                if parsed_email["report_type"] == "aggregate":
                    aggregate_reports.append(cast(OrderedDict[Any, Any], parsed_email["report"]))
                elif parsed_email["report_type"] == "forensic":
                    forensic_reports.append(cast(OrderedDict[Any, Any], parsed_email["report"]))
            except InvalidDMARCReport as error:
                logger.warning(error.__str__())
    except mailbox.NoSuchMailboxError:
        raise InvalidDMARCReport(f"Mailbox {input_} does not exist")
    return OrderedDict(
        [("aggregate_reports", aggregate_reports), ("forensic_reports", forensic_reports)]
    )


def get_dmarc_reports_from_mailbox(
    connection: MailboxConnection,
    reports_folder: str = "INBOX",
    archive_folder: str = "Archive",
    delete: bool = False,
    test: bool = False,
    ip_db_path: Optional[str] = None,
    offline: bool = False,
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 6.0,
    strip_attachment_payloads: bool = False,
    results: Optional[OrderedDict[str, List[OrderedDict]]] = None,
    batch_size: int = 10,
    create_folders: bool = True,
) -> OrderedDict[str, List[OrderedDict]]:
    """Fetches and parses DMARC reports from a mailbox

    Args:
        connection: A Mailbox connection object
        reports_folder: The folder where reports can be found
        archive_folder: The folder to move processed mail to
        delete: Delete  messages after processing them
        test: Do not move or delete messages after processing them
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        offline: Do not query online for geolocation or DNS
        nameservers: A list of DNS nameservers to query
        dns_timeout: Set the DNS query timeout
        strip_attachment_payloads: Remove attachment payloads from forensic report results
        results: Results from the previous run
        batch_size: Number of messages to read and process before saving (use 0 for no limit)
        create_folders: Whether to create the destination folders (not used in watch)

    Returns:
        OrderedDict: Lists of ``aggregate_reports`` and ``forensic_reports``
    """
    if delete and test:
        raise ValueError("delete and test options are mutually exclusive")

    if connection is None:
        raise ValueError("Must supply a connection")

    aggregate_reports = []
    forensic_reports = []
    aggregate_report_msg_uids = []
    forensic_report_msg_uids = []
    aggregate_reports_folder = f"{archive_folder}/Aggregate"
    forensic_reports_folder = f"{archive_folder}/Forensic"
    invalid_reports_folder = f"{archive_folder}/Invalid"

    if results:
        aggregate_reports = results["aggregate_reports"].copy()
        forensic_reports = results["forensic_reports"].copy()

    if not test and create_folders:
        connection.create_folder(archive_folder)
        connection.create_folder(aggregate_reports_folder)
        connection.create_folder(forensic_reports_folder)
        connection.create_folder(invalid_reports_folder)

    messages = connection.fetch_messages(reports_folder, batch_size=batch_size)
    total_messages = len(messages)
    logger.debug(f"Found {len(messages)} messages in {reports_folder}")

    if batch_size:
        message_limit = min(total_messages, batch_size)
    else:
        message_limit = total_messages

    logger.debug(f"Processing {message_limit} messages")

    for i in range(message_limit):
        msg_uid = messages[i]
        logger.debug(f"Processing message {i+1} of {message_limit}: UID {msg_uid}")
        msg_content = connection.fetch_message(msg_uid)
        try:
            sa = strip_attachment_payloads
            parsed_email = parse_report_email(
                msg_content,
                nameservers=nameservers,
                dns_timeout=dns_timeout,
                ip_db_path=ip_db_path,
                offline=offline,
                strip_attachment_payloads=sa,
                keep_alive=connection.keepalive,
            )
            if parsed_email["report_type"] == "aggregate":
                aggregate_reports.append(cast(OrderedDict[Any, Any], parsed_email["report"]))
                aggregate_report_msg_uids.append(msg_uid)
            elif parsed_email["report_type"] == "forensic":
                forensic_reports.append(cast(OrderedDict[Any, Any], parsed_email["report"]))
                forensic_report_msg_uids.append(msg_uid)
        except InvalidDMARCReport as error:
            logger.warning(error.__str__())
            if not test:
                if delete:
                    logger.debug(f"Deleting message UID {msg_uid}")
                    connection.delete_message(msg_uid)
                else:
                    logger.debug(f"Moving message UID {msg_uid} to {invalid_reports_folder}")
                    connection.move_message(msg_uid, invalid_reports_folder)

    if not test:
        if delete:
            processed_messages = aggregate_report_msg_uids + forensic_report_msg_uids

            number_of_processed_msgs = len(processed_messages)
            for i in range(number_of_processed_msgs):
                msg_uid = processed_messages[i]
                logger.debug(f"Deleting message {i+1} of {number_of_processed_msgs}: UID {msg_uid}")
                try:
                    connection.delete_message(msg_uid)

                except Exception as e:
                    logger.error(f"Mailbox error: Error deleting message UID {msg_uid}: {e!r}")
        else:
            if len(aggregate_report_msg_uids) > 0:
                logger.debug(
                    f"Moving aggregate report messages from {reports_folder} to {aggregate_reports_folder}"
                )
                number_of_agg_report_msgs = len(aggregate_report_msg_uids)
                for i in range(number_of_agg_report_msgs):
                    msg_uid = aggregate_report_msg_uids[i]
                    logger.debug(
                        f"Moving message {i+1} of {number_of_agg_report_msgs}: UID {msg_uid}"
                    )
                    try:
                        connection.move_message(msg_uid, aggregate_reports_folder)
                    except Exception as e:
                        logger.error(f"Mailbox error: Error moving message UID {msg_uid}: {e!r}")
            if len(forensic_report_msg_uids) > 0:
                logger.debug(
                    f"Moving forensic report messages from {reports_folder} to {forensic_reports_folder}"
                )
                number_of_forensic_msgs = len(forensic_report_msg_uids)
                for i in range(number_of_forensic_msgs):
                    msg_uid = forensic_report_msg_uids[i]
                    logger.debug(
                        f"Moving message {i+1} of {number_of_forensic_msgs}: UID {msg_uid}"
                    )
                    try:
                        connection.move_message(msg_uid, forensic_reports_folder)
                    except Exception as e:
                        logger.error(f"Mailbox error: Error moving message UID {msg_uid}: {e!r}")

    results = OrderedDict(
        [("aggregate_reports", aggregate_reports), ("forensic_reports", forensic_reports)]
    )

    total_messages = len(connection.fetch_messages(reports_folder))

    if not test and not batch_size and total_messages > 0:
        # Process emails that came in during the last run
        results = get_dmarc_reports_from_mailbox(
            connection=connection,
            reports_folder=reports_folder,
            archive_folder=archive_folder,
            delete=delete,
            test=test,
            nameservers=nameservers,
            dns_timeout=dns_timeout,
            strip_attachment_payloads=strip_attachment_payloads,
            results=results,
            ip_db_path=ip_db_path,
            offline=offline,
        )

    return results


def watch_inbox(
    mailbox_connection: MailboxConnection,
    callback: Callable,
    reports_folder: str = "INBOX",
    archive_folder: str = "Archive",
    delete: bool = False,
    test: bool = False,
    check_timeout: int = 30,
    ip_db_path: Optional[str] = None,
    offline: bool = False,
    nameservers: Optional[List[str]] = None,
    dns_timeout: float = 6.0,
    strip_attachment_payloads: bool = False,
    batch_size: Optional[int] = None,
) -> None:
    """Watches a mailbox for new messages and sends the results to a callback function

    Args:
        mailbox_connection: The mailbox connection object
        callback: The callback function to receive the parsing results
        reports_folder: The IMAP folder where reports can be found
        archive_folder: The folder to move processed mail to
        delete: Delete  messages after processing them
        test: Do not move or delete messages after processing them
        check_timeout: Number of seconds to wait for a IMAP IDLE response or the next mail check
        ip_db_path: Path to a MMDB file from MaxMind or DBIP
        offline: Do not query online for geolocation or DNS
        nameservers: A list of one or more nameservers to use (Cloudflare's public DNS resolvers by default)
        dns_timeout: Set the DNS query timeout
        strip_attachment_payloads: Replace attachment payloads in forensic report samples with None
        batch_size: Number of messages to read and process before saving
    """

    def check_callback(connection):
        sa = strip_attachment_payloads
        res = get_dmarc_reports_from_mailbox(
            connection=connection,
            reports_folder=reports_folder,
            archive_folder=archive_folder,
            delete=delete,
            test=test,
            ip_db_path=ip_db_path,
            offline=offline,
            nameservers=nameservers,
            dns_timeout=dns_timeout,
            strip_attachment_payloads=sa,
            batch_size=batch_size,
            create_folders=False,
        )
        callback(res)

    mailbox_connection.watch(check_callback=check_callback, check_timeout=check_timeout)


def append_json(filename: str, reports: List[OrderedDict]) -> None:
    with open(filename, "a+", newline="\n", encoding="utf-8") as output:
        output_json = json.dumps(reports, ensure_ascii=False, indent=2)
        if output.seek(0, os.SEEK_END) != 0:
            if len(reports) == 0:
                # not appending anything, don't do any dance to append it
                # correctly
                return
            output.seek(output.tell() - 1)
            last_char = output.read(1)
            if last_char == "]":
                # remove the trailing "\n]", leading "[\n", and replace with
                # ",\n"
                output.seek(output.tell() - 2)
                output.write(",\n")
                output_json = output_json[2:]
            else:
                output.seek(0)
                output.truncate()

        output.write(output_json)
    return


def append_csv(filename: str, csv: str) -> None:
    with open(filename, "a+", newline="\n", encoding="utf-8") as output:
        if output.seek(0, os.SEEK_END) != 0:
            # strip the headers from the CSV
            _headers, csv = csv.split("\n", 1)
            if len(csv) == 0:
                # not appending anything, don't do any dance to
                # append it correctly
                return
        output.write(csv)
    return


def save_output(
    results: OrderedDict[str, List[OrderedDict]],
    output_directory: str = "output",
    aggregate_json_filename: str = "aggregate.json",
    forensic_json_filename: str = "forensic.json",
    aggregate_csv_filename: str = "aggregate.csv",
    forensic_csv_filename: str = "forensic.csv",
) -> None:
    """Save report data in the given directory

    Args:
        results: Parsing results
        output_directory: The path to the directory to save in
        aggregate_json_filename: Filename for the aggregate JSON file
        forensic_json_filename: Filename for the forensic JSON file
        aggregate_csv_filename: Filename for the aggregate CSV file
        forensic_csv_filename: Filename for the forensic CSV file
    """

    aggregate_reports = results["aggregate_reports"]
    forensic_reports = results["forensic_reports"]

    if os.path.exists(output_directory):
        if not os.path.isdir(output_directory):
            raise ValueError(f"{output_directory} is not a directory")
    else:
        os.makedirs(output_directory)

    append_json(os.path.join(output_directory, aggregate_json_filename), aggregate_reports)

    append_csv(
        os.path.join(output_directory, aggregate_csv_filename),
        parsed_aggregate_reports_to_csv(aggregate_reports),
    )

    append_json(os.path.join(output_directory, forensic_json_filename), forensic_reports)

    append_csv(
        os.path.join(output_directory, forensic_csv_filename),
        parsed_forensic_reports_to_csv(forensic_reports),
    )

    samples_directory = os.path.join(output_directory, "samples")
    if not os.path.exists(samples_directory):
        os.makedirs(samples_directory)

    sample_filenames = []
    for forensic_report in forensic_reports:
        sample = forensic_report["sample"]
        message_count = 0
        parsed_sample = forensic_report["parsed_sample"]
        subject = parsed_sample["filename_safe_subject"]
        filename = subject

        while filename in sample_filenames:
            message_count += 1
            filename = f"{subject} ({message_count})"

        sample_filenames.append(filename)

        filename = f"{filename}.eml"
        path = os.path.join(samples_directory, filename)
        with open(path, "w", newline="\n", encoding="utf-8") as sample_file:
            sample_file.write(sample)
    return


def get_report_zip(results: OrderedDict[str, List[OrderedDict]]) -> bytes:
    """Creates a zip file of parsed report output

    Args:
        results: The parsed results

    Returns:
        raw zip file
    """

    def add_subdir(root_path, subdir):
        subdir_path = os.path.join(root_path, subdir)
        for subdir_root, subdir_dirs, subdir_files in os.walk(subdir_path):
            for subdir_file in subdir_files:
                subdir_file_path = os.path.join(root_path, subdir, subdir_file)
                if os.path.isfile(subdir_file_path):
                    rel_path = os.path.relpath(subdir_root, subdir_file_path)
                    subdir_arc_name = os.path.join(rel_path, subdir_file)
                    zip_file.write(subdir_file_path, subdir_arc_name)
            for subdir in subdir_dirs:
                add_subdir(subdir_path, subdir)

    storage = BytesIO()
    tmp_dir = tempfile.mkdtemp()
    try:
        save_output(results, tmp_dir)
        with zipfile.ZipFile(storage, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(tmp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        arcname = os.path.join(os.path.relpath(root, tmp_dir), file)
                        zip_file.write(file_path, arcname)
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    if os.path.isdir(dir_path):
                        zip_file.write(dir_path, directory)
                        add_subdir(root, directory)
    finally:
        shutil.rmtree(tmp_dir)

    return storage.getvalue()


def email_results(
    results: OrderedDict[str, List[OrderedDict]],
    host: str,
    mail_from: str,
    mail_to: List[str],
    mail_cc: Optional[List[str]] = None,
    mail_bcc: Optional[List[str]] = None,
    port: int = 0,
    require_encryption: bool = False,
    verify: bool = True,
    username: Optional[str] = None,
    password: Optional[str] = None,
    subject: Optional[str] = None,
    attachment_filename: Optional[str] = None,
    message: Optional[str] = None,
) -> None:
    """Emails parsing results as a zip file

    Args:
        results: Parsing results
        host: Mail server hostname or IP address
        mail_from: The value of the message from header
        mail_to: A list of addresses to mail to
        mail_cc: A list of addresses to CC
        mail_bcc: A list addresses to BCC
        port: Port to use
        require_encryption: Require a secure connection from the start
        verify: verify the SSL/TLS certificate
        username: An optional username
        password: An optional password
        subject: Overrides the default message subject
        attachment_filename: Override the default attachment filename
        message: Override the default plain text body
    """
    logger.debug(f"Emailing report to: {''.join(mail_to)}")
    date_string = datetime.now().strftime("%Y-%m-%d")
    if attachment_filename:
        if not attachment_filename.lower().endswith(".zip"):
            attachment_filename += ".zip"
        filename = attachment_filename
    else:
        filename = f"DMARC-{date_string}.zip"

    assert isinstance(mail_to, list)

    if subject is None:
        subject = f"DMARC results for {date_string}"
    if message is None:
        message = f"DMARC results for {date_string}"
    zip_bytes = get_report_zip(results)
    attachments = [(filename, zip_bytes)]

    send_email(
        host,
        mail_from,
        mail_to,
        message_cc=mail_cc,
        message_bcc=mail_bcc,
        port=port,
        require_encryption=require_encryption,
        verify=verify,
        username=username,
        password=password,
        subject=subject,
        attachments=attachments,
        plain_message=message,
    )
    return None
