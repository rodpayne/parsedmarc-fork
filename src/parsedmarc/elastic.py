# Future
from __future__ import annotations

# Standard Library
import datetime

# Installed
from elasticsearch import Elasticsearch
from elasticsearch.helpers import reindex
from elasticsearch_dsl import (
    Boolean,
    Date,
    Document,
    Index,
    InnerDoc,
    Integer,
    Ip,
    Nested,
    Object,
    Search,
    Text,
)
from elasticsearch_dsl.search import Q

# Package
from parsedmarc import AggregateReport, ForensicReport, InvalidForensicReport
from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime


class ElasticsearchError(Exception):
    """Raised when an Elasticsearch error occurs"""

    def __init__(self, message: str | Exception):
        if isinstance(message, Exception):
            message = repr(message)
        super().__init__(f"Elasticsearch Error: {message}")
        return


class _PolicyOverride(InnerDoc):
    type = Text()
    comment = Text()


class _PublishedPolicy(InnerDoc):
    domain = Text()
    adkim = Text()
    aspf = Text()
    p = Text()
    sp = Text()
    pct = Integer()
    fo = Text()


class _DKIMResult(InnerDoc):
    domain = Text()
    selector = Text()
    result = Text()


class _SPFResult(InnerDoc):
    domain = Text()
    scope = Text()
    results = Text()


class _AggregateReportDoc(Document):
    class Index:  # pylint: disable=too-few-public-methods
        name = "dmarc_aggregate"

    xml_schema = Text()
    org_name = Text()
    org_email = Text()
    org_extra_contact_info = Text()
    report_id = Text()
    date_range = Date()
    date_begin = Date()
    date_end = Date()
    errors = Text()
    published_policy = Object(_PublishedPolicy)
    source_ip_address = Ip()
    source_country = Text()
    source_reverse_dns = Text()
    source_Base_domain = Text()
    message_count = Integer
    disposition = Text()
    dkim_aligned = Boolean()
    spf_aligned = Boolean()
    passed_dmarc = Boolean()
    policy_overrides = Nested(_PolicyOverride)
    header_from = Text()
    envelope_from = Text()
    envelope_to = Text()
    dkim_results = Nested(_DKIMResult)
    spf_results = Nested(_SPFResult)

    def add_policy_override(self, type_, comment):
        self.policy_overrides.append(_PolicyOverride(type=type_, comment=comment))

    def add_dkim_result(self, domain, selector, result):
        self.dkim_results.append(_DKIMResult(domain=domain, selector=selector, result=result))

    def add_spf_result(self, domain, scope, result):
        self.spf_results.append(_SPFResult(domain=domain, scope=scope, result=result))

    def save(self, *args, **kwargs):
        self.passed_dmarc = False
        self.passed_dmarc = self.spf_aligned or self.dkim_aligned

        return super().save(*args, **kwargs)


class _EmailAddressDoc(InnerDoc):
    display_name = Text()
    address = Text()


class _EmailAttachmentDoc(Document):
    filename = Text()
    content_type = Text()
    sha256 = Text()


class _ForensicSampleDoc(InnerDoc):
    raw = Text()
    headers = Object()
    headers_only = Boolean()
    to = Nested(_EmailAddressDoc)
    subject = Text()
    filename_safe_subject = Text()
    _from = Object(_EmailAddressDoc)
    date = Date()
    reply_to = Nested(_EmailAddressDoc)
    cc = Nested(_EmailAddressDoc)
    bcc = Nested(_EmailAddressDoc)
    body = Text()
    attachments = Nested(_EmailAttachmentDoc)

    def add_to(self, display_name, address):
        self.to.append(_EmailAddressDoc(display_name=display_name, address=address))

    def add_reply_to(self, display_name, address):
        self.reply_to.append(_EmailAddressDoc(display_name=display_name, address=address))

    def add_cc(self, display_name, address):
        self.cc.append(_EmailAddressDoc(display_name=display_name, address=address))

    def add_bcc(self, display_name, address):
        self.bcc.append(_EmailAddressDoc(display_name=display_name, address=address))

    def add_attachment(self, filename, content_type, sha256):
        self.attachments.append(
            _EmailAttachmentDoc(filename=filename, content_type=content_type, sha256=sha256)
        )


class _ForensicReportDoc(Document):
    class Index:  # pylint: disable=too-few-public-methods
        name = "dmarc_forensic"

    feedback_type = Text()
    user_agent = Text()
    version = Text()
    original_mail_from = Text()
    arrival_date = Date()
    domain = Text()
    original_envelope_id = Text()
    authentication_results = Text()
    delivery_results = Text()
    source_ip_address = Ip()
    source_country = Text()
    source_reverse_dns = Text()
    source_authentication_mechanisms = Text()
    source_auth_failures = Text()
    dkim_domain = Text()
    original_rcpt_to = Text()
    sample = Object(_ForensicSampleDoc)


class AlreadySaved(ValueError):
    """Raised when a report to be saved matches an existing report"""


class ElasticsearchClient:

    def __init__(
        self,
        hosts: str | list[str],
        use_ssl: bool = False,
        ssl_cert_path: str | None = None,
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        timeout: float = 60.0,
        index_suffix: str | None = None,
        monthly_indexes: bool = True,
        number_of_shards: int = 1,
        number_of_replicas: int = 0,
    ) -> None:
        """
        Args:
            hosts: A single hostname or URL, or list of hostnames or URLs
            use_ssl: Use a HTTPS connection to the server
            ssl_cert_path: Path to the certificate chain
            username: The username to use for authentication
            password: The password to use for authentication
            api_key: The Base64 encoded API key to use for authentication
            timeout: Timeout in seconds
            index_suffix: Suffix to add to index names
            monthly_indexes: Use monthly indexes instead of daily indexes
            number_of_shards: The number of shards to use in the index
            number_of_replicas: The number of replicas to use in the index
        """
        ## Elasticsearch Client
        if isinstance(hosts, str):
            hosts = [hosts]
        conn_params = {"hosts": hosts, "timeout": timeout}
        if use_ssl:
            conn_params["use_ssl"] = True
            if ssl_cert_path:
                conn_params["verify_certs"] = True
                conn_params["ca_certs"] = ssl_cert_path
            else:
                conn_params["verify_certs"] = False
        if username and password:
            conn_params["http_auth"] = username + ":" + password
        if api_key:
            conn_params["api_key"] = api_key
        self.client = Elasticsearch(**conn_params)  # type: ignore[arg-type]

        ## Other settings
        self.aggregate_index_base = "dmarc_aggregate"
        self.forensic_index_base = "dmarc_forensic"

        if index_suffix:
            self.aggregate_index_base += f"_{index_suffix}"
            self.forensic_index_base += f"_{index_suffix}"

        self.monthly_indexes = monthly_indexes
        self.number_of_shards = number_of_shards
        self.number_of_replicas = number_of_replicas

        return

    def create_index(self, name: str) -> None:
        """Create Elasticsearch indexe

        Args:
            name: index name
        """
        index = Index(name, using=self.client)
        try:
            if not index.exists():
                logger.debug(f"Creating Elasticsearch index: {name}")
                index.settings(
                    number_of_shards=self.number_of_shards,
                    number_of_replicas=self.number_of_replicas,
                )
                index.create()
        except Exception as e:
            raise ElasticsearchError(e) from e
        return

    def migrate_indexes(self) -> None:
        """Perform any index migrations required"""
        self._migrate_indexes([self.aggregate_index_base], [self.forensic_index_base])
        return

    def _migrate_indexes(
        self,
        aggregate_indexes: list[str] | None = None,
        forensic_indexes: list[str] | None = None,
    ) -> None:
        """Update index mappings

        Args:
            aggregate_indexes: A list of aggregate index names
            forensic_indexes: A list of forensic index names
        """
        version = 2
        if aggregate_indexes is None:
            aggregate_indexes = []
        if forensic_indexes is None:
            forensic_indexes = []

        ## Migrate aggregate indexes
        for aggregate_index_name in aggregate_indexes:
            aggregate_index = Index(aggregate_index_name, using=self.client)
            if not aggregate_index.exists():
                continue
            doc = "doc"
            fo_field = "published_policy.fo"
            fo = "fo"
            fo_mapping = aggregate_index.get_field_mapping(fields=[fo_field])
            fo_mapping = fo_mapping[list(fo_mapping.keys())[0]]["mappings"]
            if doc not in fo_mapping:
                continue

            fo_mapping = fo_mapping[doc][fo_field]["mapping"][fo]
            fo_type = fo_mapping["type"]
            if fo_type == "long":
                new_index_name = f"{aggregate_index_name}-v{version}"
                body = {
                    "properties": {
                        "published_policy.fo": {
                            "type": "text",
                            "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                        }
                    }
                }
                Index(new_index_name, using=self.client).create()
                Index(new_index_name, using=self.client).put_mapping(doc_type=doc, body=body)
                reindex(self.client, aggregate_index_name, new_index_name)
                Index(aggregate_index_name, using=self.client).delete()

        # Forensic indexes do not currently need migrating
        return

    def get_index_name(self, base: str, date: datetime.datetime) -> str:
        """Get an index name based on client settings

        Args:
            base: base index name
            date: date to use to generate index
        """
        if self.monthly_indexes:
            index_date = date.strftime("%Y-%m")
        else:
            index_date = date.strftime("%Y-%m-%d")

        return f"{base}-{index_date}"

    def save_aggregate_report_to_elasticsearch(
        self,
        report: AggregateReport,
    ) -> None:
        """
        Saves a parsed DMARC aggregate report to ElasticSearch

        Args:
            report: A parsed forensic report

        Raises:
                AlreadySaved
        """
        logger.info("Saving aggregate report to Elasticsearch")
        aggregate_report = report.data.copy()
        metadata = aggregate_report["report_metadata"]
        org_name = metadata["org_name"]
        report_id = metadata["report_id"]
        domain = aggregate_report["policy_published"]["domain"]
        begin_date = human_timestamp_to_datetime(metadata["begin_date"], to_utc=True)
        end_date = human_timestamp_to_datetime(metadata["end_date"], to_utc=True)
        begin_date_human = begin_date.strftime("%Y-%m-%d %H:%M:%SZ")
        end_date_human = end_date.strftime("%Y-%m-%d %H:%M:%SZ")
        aggregate_report["begin_date"] = begin_date
        aggregate_report["end_date"] = end_date
        date_range = [aggregate_report["begin_date"], aggregate_report["end_date"]]

        org_name_query = Q({"match_phrase": {"org_name": org_name}})
        report_id_query = Q({"match_phrase": {"report_id": report_id}})
        domain_query = Q({"match_phrase": {"published_policy.domain": domain}})
        begin_date_query = Q({"match": {"date_begin": begin_date}})
        end_date_query = Q({"match": {"date_end": end_date}})

        search = Search(index=f"{self.aggregate_index_base}*", using=self.client)
        search.query = (
            org_name_query & report_id_query & domain_query & begin_date_query & end_date_query
        )

        try:
            existing = search.execute()
        except Exception as e:
            raise ElasticsearchError(f"Search for existing report error: {e!r}") from e

        if len(existing) > 0:
            raise AlreadySaved(
                f"An aggregate report ID {report_id} from {org_name} about {domain} "
                f"with a date range of {begin_date_human} UTC to {end_date_human} UTC already "
                "exists in Elasticsearch"
            )
        published_policy = _PublishedPolicy(
            domain=aggregate_report["policy_published"]["domain"],
            adkim=aggregate_report["policy_published"]["adkim"],
            aspf=aggregate_report["policy_published"]["aspf"],
            p=aggregate_report["policy_published"]["p"],
            sp=aggregate_report["policy_published"]["sp"],
            pct=aggregate_report["policy_published"]["pct"],
            fo=aggregate_report["policy_published"]["fo"],
        )

        for record in aggregate_report["records"]:
            agg_doc = _AggregateReportDoc(
                xml_schema=aggregate_report["xml_schema"],
                org_name=metadata["org_name"],
                org_email=metadata["org_email"],
                org_extra_contact_info=metadata["org_extra_contact_info"],
                report_id=metadata["report_id"],
                date_range=date_range,
                date_begin=aggregate_report["begin_date"],
                date_end=aggregate_report["end_date"],
                errors=metadata["errors"],
                published_policy=published_policy,
                source_ip_address=record["source"]["ip_address"],
                source_country=record["source"]["country"],
                source_reverse_dns=record["source"]["reverse_dns"],
                source_base_domain=record["source"]["base_domain"],
                message_count=record["count"],
                disposition=record["policy_evaluated"]["disposition"],
                dkim_aligned=record["policy_evaluated"]["dkim"] is not None
                and record["policy_evaluated"]["dkim"].lower() == "pass",
                spf_aligned=record["policy_evaluated"]["spf"] is not None
                and record["policy_evaluated"]["spf"].lower() == "pass",
                header_from=record["identifiers"]["header_from"],
                envelope_from=record["identifiers"]["envelope_from"],
                envelope_to=record["identifiers"]["envelope_to"],
            )

            for override in record["policy_evaluated"]["policy_override_reasons"]:
                agg_doc.add_policy_override(type_=override["type"], comment=override["comment"])

            for dkim_result in record["auth_results"]["dkim"]:
                agg_doc.add_dkim_result(
                    domain=dkim_result["domain"],
                    selector=dkim_result["selector"],
                    result=dkim_result["result"],
                )

            for spf_result in record["auth_results"]["spf"]:
                agg_doc.add_spf_result(
                    domain=spf_result["domain"],
                    scope=spf_result["scope"],
                    result=spf_result["result"],
                )

            index_name = self.get_index_name(self.aggregate_index_base, begin_date)
            self.create_index(index_name)
            agg_doc.meta.index = index_name

            try:
                agg_doc.save(using=self.client)
            except Exception as e:
                raise ElasticsearchError(e) from e
        return

    def save_forensic_report_to_elasticsearch(
        self,
        report: ForensicReport,
    ) -> None:
        """Save a parsed DMARC forensic report to ElasticSearch

        Args:
            report: A parsed forensic report

        Raises:
            AlreadySaved
        """
        logger.info("Saving forensic report to Elasticsearch")
        forensic_report = report.data.copy()
        sample_date = None
        if forensic_report["parsed_sample"]["date"] is not None:
            sample_date = forensic_report["parsed_sample"]["date"]
            sample_date = human_timestamp_to_datetime(sample_date)
        original_headers = forensic_report["parsed_sample"]["headers"]
        headers = {}
        for original_header in original_headers:
            headers[original_header.lower()] = original_headers[original_header]

        arrival_date_human = forensic_report["arrival_date_utc"]
        arrival_date = human_timestamp_to_datetime(arrival_date_human)

        search = Search(index=f"{self.forensic_index_base}*", using=self.client)
        q = Q({"match": {"arrival_date": arrival_date}})

        from_ = None
        to_ = None
        subject = None
        if "from" in headers:
            to_ = headers["from"]
            q &= Q({"match_phrase": {"sample.headers.from": to_}})
        if "to" in headers:
            to_ = headers["to"]
            q &= Q({"match_phrase": {"sample.headers.to": to_}})
        if "subject" in headers:
            subject = headers["subject"]
            q &= Q({"match_phrase": {"sample.headers.subject": subject}})

        search.query = q
        existing = search.execute()

        if len(existing) > 0:
            raise AlreadySaved(
                f"A forensic sample to {to_} from {from_} with a subject of {subject} "
                f"and arrival date of {arrival_date_human} already exists in Elasticsearch"
            )

        parsed_sample = forensic_report["parsed_sample"]
        sample = _ForensicSampleDoc(
            raw=forensic_report["sample"],
            headers=headers,
            headers_only=forensic_report["sample_headers_only"],
            date=sample_date,
            subject=forensic_report["parsed_sample"]["subject"],
            filename_safe_subject=parsed_sample["filename_safe_subject"],
            body=forensic_report["parsed_sample"]["body"],
        )

        for address in forensic_report["parsed_sample"]["to"]:
            sample.add_to(display_name=address["display_name"], address=address["address"])
        for address in forensic_report["parsed_sample"]["reply_to"]:
            sample.add_reply_to(display_name=address["display_name"], address=address["address"])
        for address in forensic_report["parsed_sample"]["cc"]:
            sample.add_cc(display_name=address["display_name"], address=address["address"])
        for address in forensic_report["parsed_sample"]["bcc"]:
            sample.add_bcc(display_name=address["display_name"], address=address["address"])
        for attachment in forensic_report["parsed_sample"]["attachments"]:
            sample.add_attachment(
                filename=attachment["filename"],
                content_type=attachment["mail_content_type"],
                sha256=attachment["sha256"],
            )
        try:
            forensic_doc = _ForensicReportDoc(
                feedback_type=forensic_report["feedback_type"],
                user_agent=forensic_report["user_agent"],
                version=forensic_report["version"],
                original_mail_from=forensic_report["original_mail_from"],
                arrival_date=arrival_date,
                domain=forensic_report["reported_domain"],
                original_envelope_id=forensic_report["original_envelope_id"],
                authentication_results=forensic_report["authentication_results"],
                delivery_results=forensic_report["delivery_result"],
                source_ip_address=forensic_report["source"]["ip_address"],
                source_country=forensic_report["source"]["country"],
                source_reverse_dns=forensic_report["source"]["reverse_dns"],
                source_base_domain=forensic_report["source"]["base_domain"],
                authentication_mechanisms=forensic_report["authentication_mechanisms"],
                auth_failure=forensic_report["auth_failure"],
                dkim_domain=forensic_report["dkim_domain"],
                original_rcpt_to=forensic_report["original_rcpt_to"],
                sample=sample,
            )
        except KeyError as e:
            raise InvalidForensicReport(f"Forensic report missing required field: {e!r}") from e

        index_name = self.get_index_name(self.forensic_index_base, arrival_date)
        self.create_index(index_name)
        forensic_doc.meta.index = index_name

        try:
            forensic_doc.save(using=self.client)
        except Exception as e:
            raise ElasticsearchError(e) from e
        return
