#!/usr/bin/env python3
"""A CLI for parsing DMARC reports"""

# pylint: disable=too-many-lines

# Standard Library
from argparse import ArgumentParser, Namespace
from configparser import ConfigParser
from glob import glob
from itertools import repeat
import json
import logging
from multiprocessing import Pool, Value
import multiprocessing.sharedctypes
import os
import os.path
from ssl import CERT_NONE, create_default_context
import sys
import time

# Installed
from tqdm import tqdm

# Package
from parsedmarc import (
    InvalidDMARCReport,
    ParserError,
    SortedReportContainer,
    __version__,
    elastic,
    email_results,
    get_dmarc_reports_from_mailbox,
    get_dmarc_reports_from_mbox,
    kafkaclient,
    loganalytics,
    parse_report_file,
    s3,
    save_output,
    splunk,
    syslog,
    watch_inbox,
)
from parsedmarc.log import logger
from parsedmarc.mail import GmailConnection, IMAPConnection, MSGraphConnection
from parsedmarc.mail.graph import AuthMethod
from parsedmarc.utils import is_mbox

handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter(
        fmt="%(levelname)8s:%(filename)s:%(lineno)d:%(message)s",
        datefmt="%Y-%m-%d:%H:%M:%S",
    )
)
logger.addHandler(handler)

counter: multiprocessing.sharedctypes.Synchronized


def _str_to_list(s):
    """Converts a comma separated string to a list"""
    _list = s.split(",")
    return list(map(lambda i: i.lstrip(), _list))


def cli_parse(file_path, sa, nameservers, dns_timeout, ip_db_path, offline):
    """Separated this function for multiprocessing"""
    try:
        file_results = parse_report_file(
            file_path,
            ip_db_path=ip_db_path,
            offline=offline,
            nameservers=nameservers,
            dns_timeout=dns_timeout,
            strip_attachment_payloads=sa,
        )
    except ParserError as error:
        return error, file_path
    finally:
        with counter.get_lock():
            counter.value += 1
    return file_results, file_path


def init(ctr):
    global counter  # pylint: disable=global-statement
    counter = ctr


def _main():
    """Called when the module is executed"""

    def process_reports(reports_: SortedReportContainer):
        # pylint: disable=possibly-used-before-assignment

        if not opts.silent:
            print(json.dumps(reports_.dict(), ensure_ascii=False, indent=2))

        if opts.output:
            save_output(
                results,
                output_directory=opts.output,
                aggregate_json_filename=opts.aggregate_json_filename,
                forensic_json_filename=opts.forensic_json_filename,
                aggregate_csv_filename=opts.aggregate_csv_filename,
                forensic_csv_filename=opts.forensic_csv_filename,
            )

        if opts.save_aggregate:
            for aggregate_report in reports_.aggregate_reports:
                # Elasticsearch
                if opts.elasticsearch_hosts:
                    try:
                        es_client.save_aggregate_report_to_elasticsearch(aggregate_report)
                    except elastic.AlreadySaved as warning:
                        logger.warning(str(warning))
                    except elastic.ElasticsearchError as error_:
                        logger.error(f"Elasticsearch Error: {error_!r}")
                    except Exception as error_:  # pylint: disable=broad-exception-caught
                        logger.error(f"Elasticsearch exception error: {error_!r}")

                # AWS S3
                if opts.s3_bucket:
                    try:
                        s3_client.save_aggregate_report_to_s3(aggregate_report)
                    except Exception as error_:  # pylint: disable=broad-exception-caught
                        logger.error(f"S3 Error: {error_!r}")

                # Syslog
                if opts.syslog_server:
                    try:
                        syslog_client.save_aggregate_report_to_syslog(aggregate_report)
                    except Exception as error_:  # pylint: disable=broad-exception-caught
                        logger.error(f"Syslog Error: {error_!r}")

            # store in backends that support list of reports
            # Kafka
            if opts.kafka_hosts:
                try:
                    kafka_client.save_aggregate_reports_to_kafka(
                        reports_.aggregate_reports, kafka_aggregate_topic
                    )
                except Exception as error_:  # pylint: disable=broad-exception-caught
                    logger.error(f"Kafka Error: {error_!r}")

            # Splunk HEC
            if opts.hec:
                try:
                    hec_client.save_aggregate_reports_to_splunk(reports_.aggregate_reports)
                except splunk.SplunkError as e:
                    logger.error(f"Splunk HEC error: {e!r}")

        if opts.save_forensic:
            for forensic_report in reports_.forensic_reports:
                # Elasticsearch
                if opts.elasticsearch_hosts:
                    try:
                        es_client.save_forensic_report_to_elasticsearch(forensic_report)
                    except elastic.AlreadySaved as warning:
                        logger.warning(str(warning))
                    except elastic.ElasticsearchError as error_:
                        logger.error(f"Elasticsearch Error: {error_!r}")
                    except InvalidDMARCReport as error_:
                        logger.error(str(error_))

                # AWS S3
                if opts.s3_bucket:
                    try:
                        s3_client.save_forensic_report_to_s3(forensic_report)
                    except Exception as error_:  # pylint: disable=broad-exception-caught
                        logger.error(f"S3 Error: {error_!r}")

                # Syslog
                if opts.syslog_server:
                    try:
                        syslog_client.save_forensic_report_to_syslog(forensic_report)
                    except Exception as error_:  # pylint: disable=broad-exception-caught
                        logger.error(f"Syslog Error: {error_!r}")

            # store in backends that support list of reports
            # Kafka
            if opts.kafka_hosts:
                try:
                    kafka_client.save_forensic_reports_to_kafka(
                        reports_.forensic_reports, kafka_forensic_topic
                    )
                except Exception as error_:  # pylint: disable=broad-exception-caught
                    logger.error(f"Kafka Error: {error_!r}")

            # Splunk HEC
            if opts.hec:
                try:
                    hec_client.save_forensic_reports_to_splunk(reports_.forensic_reports)
                except splunk.SplunkError as e:
                    logger.error(f"Splunk HEC error: {e!r}")

        # Store in backends that support SortedReportContainer
        # Azure LogAnalytics
        if opts.la_dce:
            try:
                la_client = loganalytics.LogAnalyticsClient(
                    client_id=opts.la_client_id,
                    client_secret=opts.la_client_secret,
                    tenant_id=opts.la_tenant_id,
                    dce=opts.la_dce,
                    dcr_immutable_id=opts.la_dcr_immutable_id,
                    dcr_aggregate_stream=opts.la_dcr_aggregate_stream,
                    dcr_forensic_stream=opts.la_dcr_forensic_stream,
                )
                la_client.publish_results(reports_, opts.save_aggregate, opts.save_forensic)
            except loganalytics.LogAnalyticsException as e:
                logger.error(f"Log Analytics error: {e!r}")
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error(f"Unknown error occured during the publishing to Log Analitics: {e!r}")
        return

    arg_parser = ArgumentParser(description="Parses DMARC reports")
    arg_parser.add_argument(
        "-c",
        "--config-file",
        help="a path to a configuration file (--silent implied)",
    )
    arg_parser.add_argument(
        "file_path",
        nargs="*",
        help="one or more paths to aggregate or forensic report files, emails, or mbox files",
    )
    arg_parser.add_argument(
        "--strip-attachment-payloads",
        help="remove attachment payloads from forensic report output",
        action="store_true",
    )
    arg_parser.add_argument("-o", "--output", help="write output files to the given directory")
    arg_parser.add_argument(
        "--aggregate-json-filename",
        help="filename for the aggregate JSON output file",
        default="aggregate.json",
    )
    arg_parser.add_argument(
        "--forensic-json-filename",
        help="filename for the forensic JSON output file",
        default="forensic.json",
    )
    arg_parser.add_argument(
        "--aggregate-csv-filename",
        help="filename for the aggregate CSV output file",
        default="aggregate.csv",
    )
    arg_parser.add_argument(
        "--forensic-csv-filename",
        help="filename for the forensic CSV output file",
        default="forensic.csv",
    )
    arg_parser.add_argument("-n", "--nameservers", nargs="+", help="nameservers to query")
    arg_parser.add_argument(
        "-t",
        "--dns_timeout",
        help="number of seconds to wait for an answer from DNS (default: 2.0)",
        type=float,
        default=2.0,
    )
    arg_parser.add_argument(
        "--offline",
        action="store_true",
        help="do not make online queries for geolocation  or  DNS",
    )
    arg_parser.add_argument("-s", "--silent", action="store_true", help="only print errors")
    arg_parser.add_argument(
        "-w",
        "--warnings",
        action="store_true",
        help="print warnings in addition to errors",
    )
    arg_parser.add_argument("--verbose", action="store_true", help="more verbose output")
    arg_parser.add_argument("--debug", action="store_true", help="print debugging information")
    arg_parser.add_argument("--log-file", default=None, help="output logging to a file")
    arg_parser.add_argument("-v", "--version", action="version", version=__version__)

    reports = SortedReportContainer()

    args = arg_parser.parse_args()

    default_gmail_api_scope = "https://www.googleapis.com/auth/gmail.modify"

    opts = Namespace(
        file_path=args.file_path,
        config_file=args.config_file,
        offline=args.offline,
        strip_attachment_payloads=args.strip_attachment_payloads,
        output=args.output,
        aggregate_csv_filename=args.aggregate_csv_filename,
        aggregate_json_filename=args.aggregate_json_filename,
        forensic_csv_filename=args.forensic_csv_filename,
        forensic_json_filename=args.forensic_json_filename,
        nameservers=args.nameservers,
        silent=args.silent,
        warnings=args.warnings,
        dns_timeout=args.dns_timeout,
        debug=args.debug,
        verbose=args.verbose,
        save_aggregate=False,
        save_forensic=False,
        mailbox_reports_folder="INBOX",
        mailbox_archive_folder="Archive",
        mailbox_watch=False,
        mailbox_delete=False,
        mailbox_test=False,
        mailbox_batch_size=None,
        mailbox_check_timeout=30,
        imap_host=None,
        imap_skip_certificate_verification=False,
        imap_ssl=True,
        imap_port=993,
        imap_timeout=30,
        imap_max_retries=4,
        imap_user=None,
        imap_password=None,
        graph_auth_method=None,
        graph_user=None,
        graph_password=None,
        graph_client_id=None,
        graph_client_secret=None,
        graph_tenant_id=None,
        graph_mailbox=None,
        graph_allow_unencrypted_storage=False,
        hec=None,
        hec_token=None,
        hec_index=None,
        hec_skip_certificate_verification=False,
        elasticsearch_hosts=None,
        elasticsearch_timeout=60,
        elasticsearch_number_of_shards=1,
        elasticsearch_number_of_replicas=0,
        elasticsearch_index_suffix=None,
        elasticsearch_ssl=True,
        elasticsearch_ssl_cert_path=None,
        elasticsearch_monthly_indexes=False,
        elasticsearch_username=None,
        elasticsearch_password=None,
        elasticsearch_api_key=None,
        kafka_hosts=None,
        kafka_username=None,
        kafka_password=None,
        kafka_aggregate_topic=None,
        kafka_forensic_topic=None,
        kafka_ssl=False,
        kafka_skip_certificate_verification=False,
        smtp_host=None,
        smtp_port=25,
        smtp_ssl=False,
        smtp_skip_certificate_verification=False,
        smtp_user=None,
        smtp_password=None,
        smtp_from=None,
        smtp_to=[],
        smtp_subject="parsedmarc report",
        smtp_message="Please see the attached DMARC results.",
        s3_bucket=None,
        s3_path=None,
        s3_region_name=None,
        s3_endpoint_url=None,
        s3_access_key_id=None,
        s3_secret_access_key=None,
        syslog_server=None,
        syslog_port=None,
        gmail_api_credentials_file=None,
        gmail_api_token_file=None,
        gmail_api_include_spam_trash=False,
        gmail_api_scopes=[],
        gmail_api_oauth2_port=8080,
        log_file=args.log_file,
        n_procs=1,
        chunk_size=1,
        ip_db_path=None,
        la_client_id=None,
        la_client_secret=None,
        la_tenant_id=None,
        la_dce=None,
        la_dcr_immutable_id=None,
        la_dcr_aggregate_stream=None,
        la_dcr_forensic_stream=None,
    )
    args = arg_parser.parse_args()

    if args.config_file:
        abs_path = os.path.abspath(args.config_file)
        if not os.path.exists(abs_path):
            logger.error(f"A file does not exist at {abs_path}")
            sys.exit(-1)
        opts.silent = True
        config = ConfigParser()
        config.read(args.config_file)
        if "general" in config.sections():
            general_config = config["general"]
            if "offline" in general_config:
                opts.offline = general_config.getboolean("offline")
            if "strip_attachment_payloads" in general_config:
                opts.strip_attachment_payloads = general_config.getboolean(
                    "strip_attachment_payloads"
                )
            if "output" in general_config:
                opts.output = general_config["output"]
            if "aggregate_json_filename" in general_config:
                opts.aggregate_json_filename = general_config["aggregate_json_filename"]
            if "forensic_json_filename" in general_config:
                opts.forensic_json_filename = general_config["forensic_json_filename"]
            if "aggregate_csv_filename" in general_config:
                opts.aggregate_csv_filename = general_config["aggregate_csv_filename"]
            if "forensic_csv_filename" in general_config:
                opts.forensic_csv_filename = general_config["forensic_csv_filename"]
            if "nameservers" in general_config:
                opts.nameservers = _str_to_list(general_config["nameservers"])
            if "dns_timeout" in general_config:
                opts.dns_timeout = general_config.getfloat("dns_timeout")
            if "save_aggregate" in general_config:
                opts.save_aggregate = general_config["save_aggregate"]
            if "save_forensic" in general_config:
                opts.save_forensic = general_config["save_forensic"]
            if "debug" in general_config:
                opts.debug = general_config.getboolean("debug")
            if "verbose" in general_config:
                opts.verbose = general_config.getboolean("verbose")
            if "silent" in general_config:
                opts.silent = general_config.getboolean("silent")
            if "warnings" in general_config:
                opts.warnings = general_config.getboolean("warnings")
            if "log_file" in general_config:
                opts.log_file = general_config["log_file"]
            if "n_procs" in general_config:
                opts.n_procs = general_config.getint("n_procs")
            if "chunk_size" in general_config:
                opts.chunk_size = general_config.getint("chunk_size")
            opts.ip_db_path = general_config.get("ip_db_path")

        if "mailbox" in config.sections():
            mailbox_config = config["mailbox"]
            if "msgraph" in config.sections():
                opts.mailbox_reports_folder = "Inbox"
            if "reports_folder" in mailbox_config:
                opts.mailbox_reports_folder = mailbox_config["reports_folder"]
            if "archive_folder" in mailbox_config:
                opts.mailbox_archive_folder = mailbox_config["archive_folder"]
            if "watch" in mailbox_config:
                opts.mailbox_watch = mailbox_config.getboolean("watch")
            if "delete" in mailbox_config:
                opts.mailbox_delete = mailbox_config.getboolean("delete")
            if "test" in mailbox_config:
                opts.mailbox_test = mailbox_config.getboolean("test")
            if "batch_size" in mailbox_config:
                opts.mailbox_batch_size = mailbox_config.getint("batch_size")
            if "check_timeout" in mailbox_config:
                opts.mailbox_check_timeout = mailbox_config.getint("check_timeout")

        if "imap" in config.sections():
            imap_config = config["imap"]
            if "watch" in imap_config:
                logger.warning(
                    "Starting in 8.0.0, the watch option has been "
                    "moved from the imap configuration section to "
                    "the mailbox configuration section."
                )
            if "host" in imap_config:
                opts.imap_host = imap_config["host"]
            else:
                logger.error("host setting missing from the imap config section")
                sys.exit(-1)
            if "port" in imap_config:
                opts.imap_port = imap_config.getint("port")
            if "timeout" in imap_config:
                opts.imap_timeout = imap_config.getfloat("timeout")
            if "max_retries" in imap_config:
                opts.imap_max_retries = imap_config.getint("max_retries")
            if "ssl" in imap_config:
                opts.imap_ssl = imap_config.getboolean("ssl")
            if "skip_certificate_verification" in imap_config:
                imap_verify = imap_config.getboolean("skip_certificate_verification")
                opts.imap_skip_certificate_verification = imap_verify
            if "user" in imap_config:
                opts.imap_user = imap_config["user"]
            else:
                logger.critical("user setting missing from the imap config section")
                sys.exit(-1)
            if "password" in imap_config:
                opts.imap_password = imap_config["password"]
            else:
                logger.critical("password setting missing from the imap config section")
                sys.exit(-1)
            if "reports_folder" in imap_config:
                opts.mailbox_reports_folder = imap_config["reports_folder"]
                logger.warning(
                    "Use of the reports_folder option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "archive_folder" in imap_config:
                opts.mailbox_archive_folder = imap_config["archive_folder"]
                logger.warning(
                    "Use of the archive_folder option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "watch" in imap_config:
                opts.mailbox_watch = imap_config.getboolean("watch")
                logger.warning(
                    "Use of the watch option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "delete" in imap_config:
                logger.warning(
                    "Use of the delete option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "test" in imap_config:
                opts.mailbox_test = imap_config.getboolean("test")
                logger.warning(
                    "Use of the test option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "batch_size" in imap_config:
                opts.mailbox_batch_size = imap_config.getint("batch_size")
                logger.warning(
                    "Use of the batch_size option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )

        if "msgraph" in config.sections():
            graph_config = config["msgraph"]
            opts.graph_token_file = graph_config.get("token_file", ".token")

            if "auth_method" not in graph_config:
                logger.info(
                    "auth_method setting missing from the "
                    "msgraph config section "
                    "defaulting to UsernamePassword"
                )
                opts.graph_auth_method = AuthMethod.UsernamePassword.name
            else:
                opts.graph_auth_method = graph_config["auth_method"]

            if opts.graph_auth_method == AuthMethod.UsernamePassword.name:
                if "user" in graph_config:
                    opts.graph_user = graph_config["user"]
                else:
                    logger.critical("user setting missing from the msgraph config section")
                    sys.exit(-1)
                if "password" in graph_config:
                    opts.graph_password = graph_config["password"]
                else:
                    logger.critical("password setting missing from the msgraph config section")
                    sys.exit(-1)

            if opts.graph_auth_method != AuthMethod.UsernamePassword.name:
                if "tenant_id" in graph_config:
                    opts.graph_tenant_id = graph_config["tenant_id"]
                else:
                    logger.critical("tenant_id setting missing from the msgraph config section")
                    sys.exit(-1)

            if "client_secret" in graph_config:
                opts.graph_client_secret = graph_config["client_secret"]
            else:
                logger.critical("client_secret setting missing from the msgraph config section")
                sys.exit(-1)

            if "client_id" in graph_config:
                opts.graph_client_id = graph_config["client_id"]
            else:
                logger.critical("client_id setting missing from the msgraph config section")
                sys.exit(-1)

            if "mailbox" in graph_config:
                opts.graph_mailbox = graph_config["mailbox"]
            elif opts.graph_auth_method != AuthMethod.UsernamePassword.name:
                logger.critical("mailbox setting missing from the msgraph config section")
                sys.exit(-1)

            if "allow_unencrypted_storage" in graph_config:
                opts.graph_allow_unencrypted_storage = graph_config.getboolean(
                    "allow_unencrypted_storage"
                )

        if "elasticsearch" in config:
            elasticsearch_config = config["elasticsearch"]
            if "hosts" in elasticsearch_config:
                opts.elasticsearch_hosts = _str_to_list(elasticsearch_config["hosts"])
            else:
                logger.critical("hosts setting missing from the elasticsearch config section")
                sys.exit(-1)
            if "timeout" in elasticsearch_config:
                opts.elasticsearch_timeout = elasticsearch_config.getfloat("timeout")
            if "number_of_shards" in elasticsearch_config:
                opts.elasticsearch_number_of_shards = elasticsearch_config.getint(
                    "number_of_shards"
                )
            if "number_of_replicas" in elasticsearch_config:
                opts.elasticsearch_number_of_replicas = elasticsearch_config.getint(
                    "number_of_replicas"
                )
            if "index_suffix" in elasticsearch_config:
                opts.elasticsearch_index_suffix = elasticsearch_config["index_suffix"]
            if "monthly_indexes" in elasticsearch_config:
                opts.elasticsearch_monthly_indexes = elasticsearch_config.getboolean(
                    "monthly_indexes"
                )
            if "ssl" in elasticsearch_config:
                opts.elasticsearch_ssl = elasticsearch_config.getboolean("ssl")
            if "cert_path" in elasticsearch_config:
                opts.elasticsearch_ssl_cert_path = elasticsearch_config["cert_path"]
            if "user" in elasticsearch_config:
                opts.elasticsearch_username = elasticsearch_config["user"]
            if "password" in elasticsearch_config:
                opts.elasticsearch_password = elasticsearch_config["password"]
            if "api_key" in elasticsearch_config:
                opts.elasticsearch_api_key = elasticsearch_config["api_key"]
        if "splunk_hec" in config.sections():
            hec_config = config["splunk_hec"]
            if "url" in hec_config:
                opts.hec = hec_config["url"]
            else:
                logger.critical("url setting missing from the splunk_hec config section")
                sys.exit(-1)
            if "token" in hec_config:
                opts.hec_token = hec_config["token"]
            else:
                logger.critical("token setting missing from the splunk_hec config section")
                sys.exit(-1)
            if "index" in hec_config:
                opts.hec_index = hec_config["index"]
            else:
                logger.critical("index setting missing from the splunk_hec config section")
                sys.exit(-1)
            if "skip_certificate_verification" in hec_config:
                opts.hec_skip_certificate_verification = hec_config["skip_certificate_verification"]
        if "kafka" in config.sections():
            kafka_config = config["kafka"]
            if "hosts" in kafka_config:
                opts.kafka_hosts = _str_to_list(kafka_config["hosts"])
            else:
                logger.critical("hosts setting missing from the kafka config section")
                sys.exit(-1)
            if "user" in kafka_config:
                opts.kafka_username = kafka_config["user"]
            else:
                logger.critical("user setting missing from the kafka config section")
                sys.exit(-1)
            if "password" in kafka_config:
                opts.kafka_password = kafka_config["password"]
            else:
                logger.critical("password setting missing from the kafka config section")
                sys.exit(-1)
            if "ssl" in kafka_config:
                opts.kafka_ssl = kafka_config.getboolean("ssl")
            if "skip_certificate_verification" in kafka_config:
                opts.kafka_skip_certificate_verification = kafka_config.getboolean(
                    "skip_certificate_verification"
                )
            if "aggregate_topic" in kafka_config:
                opts.kafka_aggregate_topic = kafka_config["aggregate_topic"]
            else:
                logger.critical("aggregate_topic setting missing from the kafka config section")
                sys.exit(-1)
            if "forensic_topic" in kafka_config:
                opts.kafka_forensic_topic = kafka_config["forensic_topic"]
            else:
                logger.critical("forensic_topic setting missing from the splunk_hec config section")
        if "smtp" in config.sections():
            smtp_config = config["smtp"]
            if "host" in smtp_config:
                opts.smtp_host = smtp_config["host"]
            else:
                logger.critical("host setting missing from the smtp config section")
                sys.exit(-1)
            if "port" in smtp_config:
                opts.smtp_port = smtp_config.getint("port")
            if "ssl" in smtp_config:
                opts.smtp_ssl = smtp_config.getboolean("ssl")
            if "skip_certificate_verification" in smtp_config:
                smtp_verify = smtp_config.getboolean("skip_certificate_verification")
                opts.smtp_skip_certificate_verification = smtp_verify
            if "user" in smtp_config:
                opts.smtp_user = smtp_config["user"]
            else:
                logger.critical("user setting missing from the smtp config section")
                sys.exit(-1)
            if "password" in smtp_config:
                opts.smtp_password = smtp_config["password"]
            else:
                logger.critical("password setting missing from the smtp config section")
                sys.exit(-1)
            if "from" in smtp_config:
                opts.smtp_from = smtp_config["from"]
            else:
                logger.critical("from setting missing from the smtp config section")
            if "to" in smtp_config:
                opts.smtp_to = _str_to_list(smtp_config["to"])
            else:
                logger.critical("to setting missing from the smtp config section")
            if "subject" in smtp_config:
                opts.smtp_subject = smtp_config["subject"]
            if "attachment" in smtp_config:
                opts.smtp_attachment = smtp_config["attachment"]
            if "message" in smtp_config:
                opts.smtp_message = smtp_config["message"]
        if "s3" in config.sections():
            s3_config = config["s3"]
            if "bucket" in s3_config:
                opts.s3_bucket = s3_config["bucket"]
            else:
                logger.critical("bucket setting missing from the s3 config section")
                sys.exit(-1)
            opts.s3_path = s3_config.get("path", "").strip("/")

            if "region_name" in s3_config:
                opts.s3_region_name = s3_config["region_name"]
            if "endpoint_url" in s3_config:
                opts.s3_endpoint_url = s3_config["endpoint_url"]
            if "access_key_id" in s3_config:
                opts.s3_access_key_id = s3_config["access_key_id"]
            if "secret_access_key" in s3_config:
                opts.s3_secret_access_key = s3_config["secret_access_key"]

        if "syslog" in config.sections():
            syslog_config = config["syslog"]
            if "server" in syslog_config:
                opts.syslog_server = syslog_config["server"]
            else:
                logger.critical("server setting missing from the syslog config section")
                sys.exit(-1)
            opts.syslog_port = syslog_config.get("port", 514)

        if "gmail_api" in config.sections():
            gmail_api_config = config["gmail_api"]
            opts.gmail_api_credentials_file = gmail_api_config.get("credentials_file")
            opts.gmail_api_token_file = gmail_api_config.get("token_file", ".token")
            opts.gmail_api_include_spam_trash = gmail_api_config.getboolean(
                "include_spam_trash", False
            )
            opts.gmail_api_scopes = gmail_api_config.get("scopes", default_gmail_api_scope)
            opts.gmail_api_scopes = _str_to_list(opts.gmail_api_scopes)
            if "oauth2_port" in gmail_api_config:
                opts.gmail_api_oauth2_port = gmail_api_config.get("oauth2_port", 8080)
        if "log_analytics" in config.sections():
            log_analytics_config = config["log_analytics"]
            opts.la_client_id = log_analytics_config.get("client_id")
            opts.la_client_secret = log_analytics_config.get("client_secret")
            opts.la_tenant_id = log_analytics_config.get("tenant_id")
            opts.la_dce = log_analytics_config.get("dce")
            opts.la_dcr_immutable_id = log_analytics_config.get("dcr_immutable_id")
            opts.la_dcr_aggregate_stream = log_analytics_config.get("dcr_aggregate_stream")
            opts.la_dcr_forensic_stream = log_analytics_config.get("dcr_forensic_stream")

    logger.setLevel(logging.ERROR)

    if opts.warnings:
        logger.setLevel(logging.WARNING)
    if opts.verbose:
        logger.setLevel(logging.INFO)
    if opts.debug:
        logger.setLevel(logging.DEBUG)
    if opts.log_file:
        try:
            # check log file is writable
            with open(opts.log_file, "w", encoding="utf8"):
                pass
            fh = logging.FileHandler(opts.log_file)
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
                )
            )
            logger.addHandler(fh)
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger.warning(f"Unable to write to log file: {error!r}")

    if (
        opts.imap_host is None
        and opts.graph_client_id is None
        and opts.gmail_api_credentials_file is None
        and len(args.file_path) == 0
    ):
        logger.error("You must supply input files or a mailbox connection")
        sys.exit(1)

    logger.info("Starting parsedmarc")

    if opts.save_aggregate or opts.save_forensic:
        try:
            if opts.elasticsearch_hosts:
                es_client = elastic.ElasticsearchClient(
                    opts.elasticsearch_hosts,
                    opts.elasticsearch_ssl,
                    opts.elasticsearch_ssl_cert_path,
                    opts.elasticsearch_username,
                    opts.elasticsearch_password,
                    opts.elasticsearch_api_key,
                    opts.elasticsearch_timeout,
                    opts.elasticsearch_index_suffix,
                    opts.elasticsearch_monthly_indexes,
                    opts.elasticsearch_number_of_shards,
                    opts.elasticsearch_number_of_replicas,
                )
                es_client.migrate_indexes()
        except elastic.ElasticsearchError:
            logger.exception("Elasticsearch Error")
            sys.exit(1)

    if opts.s3_bucket:
        try:
            s3_client = s3.S3Client(
                bucket_name=opts.s3_bucket,
                bucket_path=opts.s3_path,
                region_name=opts.s3_region_name,
                endpoint_url=opts.s3_endpoint_url,
                access_key_id=opts.s3_access_key_id,
                secret_access_key=opts.s3_secret_access_key,
            )
        except Exception as error_:  # pylint: disable=broad-exception-caught
            logger.error(f"S3 Error: {error_!r}")

    if opts.syslog_server:
        try:
            syslog_client = syslog.SyslogClient(
                server_name=opts.syslog_server,
                server_port=int(opts.syslog_port),
            )
        except Exception as error_:  # pylint: disable=broad-exception-caught
            logger.error(f"Syslog Error: {error_!r}")

    if opts.hec:
        if opts.hec_token is None or opts.hec_index is None:
            logger.error("HEC token and HEC index are required when using HEC URL")
            sys.exit(1)

        verify = True
        if opts.hec_skip_certificate_verification:
            verify = False
        hec_client = splunk.HECClient(opts.hec, opts.hec_token, opts.hec_index, verify=verify)

    if opts.kafka_hosts:
        try:
            ssl_context = None
            if opts.kafka_skip_certificate_verification:
                logger.debug("Skipping Kafka certificate verification")
                ssl_context = create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = CERT_NONE
            kafka_client = kafkaclient.KafkaClient(
                opts.kafka_hosts,
                username=opts.kafka_username,
                password=opts.kafka_password,
                ssl_context=ssl_context,
            )
        except Exception as error_:  # pylint: disable=broad-exception-caught
            logger.error(f"Kafka Error: {error_!r}")

    kafka_aggregate_topic = opts.kafka_aggregate_topic
    kafka_forensic_topic = opts.kafka_forensic_topic

    file_paths = []
    mbox_paths = []

    for file_path in args.file_path:
        file_paths += glob(file_path)
    for file_path in file_paths:
        if is_mbox(file_path):
            mbox_paths.append(file_path)

    file_paths = [p for p in set(file_paths) if os.path.isfile(p)]
    mbox_paths = [p for p in set(mbox_paths) if os.path.isfile(p)]

    for mbox_path in mbox_paths:
        file_paths.remove(mbox_path)

    counter = Value("i", 0)  # pylint: disable=redefined-outer-name
    with Pool(opts.n_procs, initializer=init, initargs=(counter,)) as pool:
        results = pool.starmap_async(
            cli_parse,
            zip(
                file_paths,
                repeat(opts.strip_attachment_payloads),
                repeat(opts.nameservers),
                repeat(opts.dns_timeout),
                repeat(opts.ip_db_path),
                repeat(opts.offline),
            ),
            opts.chunk_size,
        )
        if sys.stdout.isatty():
            pbar = tqdm(total=len(file_paths))
            while not results.ready():
                pbar.update(counter.value - pbar.n)
                time.sleep(0.1)
            pbar.close()
        else:
            while not results.ready():
                time.sleep(0.1)
        results = results.get()
        pool.close()
        pool.join()

    for result in results:
        if isinstance(result[0], InvalidDMARCReport):
            logger.error(f"Failed to parse {result[1]} - {result[0]}")
        else:
            reports.add_report(result[0])

    for mbox_path in mbox_paths:
        strip = opts.strip_attachment_payloads
        reports = get_dmarc_reports_from_mbox(
            mbox_path,
            nameservers=opts.nameservers,
            dns_timeout=opts.dns_timeout,
            strip_attachment_payloads=strip,
            ip_db_path=opts.ip_db_path,
            offline=opts.offline,
        )
        reports.aggregate_reports += reports.aggregate_reports
        reports.forensic_reports += reports.forensic_reports

    mailbox_connection = None
    if opts.imap_host:
        try:
            if opts.imap_user is None or opts.imap_password is None:
                logger.error("IMAP user and password must be specified ifhost is specified")

            ssl = True
            verify = True
            if opts.imap_skip_certificate_verification:
                logger.debug("Skipping IMAP certificate verification")
                verify = False
            if opts.imap_ssl is False:
                ssl = False

            mailbox_connection = IMAPConnection(
                host=opts.imap_host,
                port=opts.imap_port,
                ssl=ssl,
                verify=verify,
                timeout=opts.imap_timeout,
                max_retries=opts.imap_max_retries,
                user=opts.imap_user,
                password=opts.imap_password,
            )

        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("IMAP Error")
            sys.exit(1)

    if opts.graph_client_id:
        try:
            mailbox = opts.graph_mailbox or opts.graph_user
            mailbox_connection = MSGraphConnection(
                auth_method=opts.graph_auth_method,
                mailbox=mailbox,
                tenant_id=opts.graph_tenant_id,
                client_id=opts.graph_client_id,
                client_secret=opts.graph_client_secret,
                username=opts.graph_user,
                password=opts.graph_password,
                token_file=opts.graph_token_file,
                allow_unencrypted_storage=opts.graph_allow_unencrypted_storage,
            )

        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("MS Graph Error")
            sys.exit(1)

    if opts.gmail_api_credentials_file:
        if opts.mailbox_delete:
            if "https://mail.google.com/" not in opts.gmail_api_scopes:
                logger.error(
                    "Message deletion requires scope"
                    " 'https://mail.google.com/'. "
                    "Add the scope and remove token file "
                    "to acquire proper access."
                )
                opts.mailbox_delete = False

        try:
            mailbox_connection = GmailConnection(
                credentials_file=opts.gmail_api_credentials_file,
                token_file=opts.gmail_api_token_file,
                scopes=opts.gmail_api_scopes,
                include_spam_trash=opts.gmail_api_include_spam_trash,
                reports_folder=opts.mailbox_reports_folder,
                oauth2_port=opts.gmail_api_oauth2_port,
            )

        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Gmail API Error")
            sys.exit(1)

    if mailbox_connection:
        try:
            reports = get_dmarc_reports_from_mailbox(
                connection=mailbox_connection,
                delete=opts.mailbox_delete,
                batch_size=opts.mailbox_batch_size,
                reports_folder=opts.mailbox_reports_folder,
                archive_folder=opts.mailbox_archive_folder,
                ip_db_path=opts.ip_db_path,
                offline=opts.offline,
                nameservers=opts.nameservers,
                dns_timeout=opts.dns_timeout,
                test=opts.mailbox_test,
                strip_attachment_payloads=opts.strip_attachment_payloads,
            )

            reports.aggregate_reports += reports["aggregate_reports"]
            reports.forensic_reports += reports["forensic_reports"]

        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Mailbox Error")
            sys.exit(1)

    process_reports(reports)

    if opts.smtp_host:
        try:
            verify = True
            if opts.smtp_skip_certificate_verification:
                verify = False
            email_results(
                reports,
                opts.smtp_host,
                opts.smtp_from,
                opts.smtp_to,
                port=opts.smtp_port,
                verify=verify,
                username=opts.smtp_user,
                password=opts.smtp_password,
                subject=opts.smtp_subject,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("Failed to email results")
            sys.exit(1)

    if mailbox_connection and opts.mailbox_watch:
        logger.info("Watching for email - Quit with ctrl-c")

        try:
            watch_inbox(
                mailbox_connection=mailbox_connection,
                callback=process_reports,
                reports_folder=opts.mailbox_reports_folder,
                archive_folder=opts.mailbox_archive_folder,
                delete=opts.mailbox_delete,
                test=opts.mailbox_test,
                check_timeout=opts.mailbox_check_timeout,
                nameservers=opts.nameservers,
                dns_timeout=opts.dns_timeout,
                strip_attachment_payloads=opts.strip_attachment_payloads,
                batch_size=opts.mailbox_batch_size,
                ip_db_path=opts.ip_db_path,
                offline=opts.offline,
            )
        except FileExistsError as error:
            logger.error(f"{error!r}")
            sys.exit(1)


if __name__ == "__main__":
    _main()
