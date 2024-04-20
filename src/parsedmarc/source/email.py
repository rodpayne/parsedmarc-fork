### IMPORTS
### ============================================================================
# Future
from __future__ import annotations

# Standard Library
from collections import deque
import time
from typing import Literal

# Local
from .. import mail
from ..parser import InvalidDMARCReport
from .base import BaseConfig, Job, JobStatus, Source, SourceState


### CLASSES
### ============================================================================
class MailboxConnectionSource(Source):
    """Base class for `MailboxConnection` based sources

    Child classes MUST set the `self.mailbox` attribute.
    """

    config: MailboxConfig
    mailbox: mail.MailboxConnection

    def setup(self) -> None:
        if self._state != SourceState.SHUTDOWN:
            raise RuntimeError("Source is already running")

        # Note: We do not set _state = RUNNING or use try catch block as this code should be stable
        # and is intended to always be called via a `super().setup()` call in child classses.

        self._message_queue: deque[str] = deque()
        self._last_keep_alive: float = 0

        self._state = SourceState.SETTING_UP
        return

    def get_job(self) -> Job | None:
        if self._state != SourceState.RUNNING:
            raise RuntimeError("Source is not running")

        if not self._message_queue:
            self._message_queue.extend(self.mailbox.fetch_messages(self.config.reports_folder))

        if self._message_queue:
            message_id = self._message_queue.popleft()
            raw_email = self.mailbox.fetch_message(message_id)
            try:
                report = self.parser.parse_report_email(raw_email)
                job = Job(source=self, report=report, identifier=message_id)
                self.register_job(job)
                return job

            except InvalidDMARCReport as error:
                self.logger.warning(repr(error))
                if self.config.mode == "archive":
                    self.debug(
                        f"Moving invalid message: {message_id} to {self.config.invalid_folder}"
                    )
                    self.mailbox.move_message(message_id, self.config.invalid_folder)
                elif self.config.mode == "delete":
                    self.debug(f"Deleting invalid message: {message_id}")
                    self.mailbox.delete_message(message_id)

        ## No pending messages
        if time.time() - self._last_keep_alive > 30:
            self.mailbox.keepalive()
            self._last_keep_alive = time.time()

        return None

    def ack_job(self, job: Job, status: JobStatus) -> None:
        if self._state != SourceState.RUNNING:
            raise RuntimeError("Source is not running")

        if status == JobStatus.SUCCESS:
            message_id = job.identifier
            if self.config.mode == "archive":
                self.debug(
                    f"Moving processed message: {message_id} to {self.config.archive_folder}"
                )
                self.mailbox.move_message(message_id, self.config.archive_folder)
            elif self.config.mode == "delete":
                self.debug(f"Deleting processed message: {message_id}")
                self.mailbox.delete_message(message_id)

        elif status in {JobStatus.CANCELLED, JobStatus.ERROR}:
            # Do nothing - we want it to stay so we can try get it again next time.
            pass

        else:
            raise NotImplementedError(f"{self.__class__.__name__} does not support {status=}")

        super().ack_job(job, status)
        return


class MailboxConfig(BaseConfig):
    reports_folder: str = "INBOX"
    archive_folder: str = "Archive"
    invalid_folder: str = "Invalid"
    mode: Literal["test", "archive", "delete"] = "archive"


## IMAP
## -----------------------------------------------------------------------------
class Imap(MailboxConnectionSource):
    """Source that collects emails using IMAP"""

    config: ImapConfig

    def setup(self) -> None:
        super().setup()
        try:
            self.mailbox = mail.IMAPConnection(
                host=self.config.host,
                user=self.config.username,
                password=self.config.password,
                port=self.config.port,
                ssl=self.config.ssl,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
                max_retries=self.config.max_retries,
            )
        except Exception:
            self._state = SourceState.SETUP_ERROR
            raise

        self._state = SourceState.RUNNING
        return


class ImapConfig(MailboxConfig):
    host: str  # IMAP host to connect to
    username: str  # IMAP Username
    password: str  # IMAP Password
    port: int | None = (
        None  # Port to connect to, if `None` will use the default IMAP port based on the SSL/TLS settings
    )
    ssl: bool = True  # Use SSL/TLS
    verify_ssl: bool = True  # Verify SSL/TLS certificate
    timeout: int = 30  # Timout in seconds for underlying IMAP operations
    max_retries: int = 4  # Max number of attempts before giving up


## Google
## -----------------------------------------------------------------------------
class Google(MailboxConnectionSource):
    """Source for connecting to Google accounts using the Google API.

    Supports both Gmail and Google Workspace accounts.
    """

    config: GoogleConfig

    def setup(self) -> None:
        super().setup()
        try:
            self.mailbox = mail.GmailConnection(
                credentials_file=self.config.credentials_file,
                token_file=self.config.token_file,
                scopes=self.config.scopes,
                include_spam_trash=self.config.include_spam_trash,
                reports_folder=self.config.reports_folder,
                oauth2_port=self.config.oauth2_port,
            )
        except Exception:
            self._state = SourceState.SETUP_ERROR
            raise

        self._state = SourceState.RUNNING
        return


class GoogleConfig(MailboxConfig):
    credentials_file: str  # Path to file containing the credentials
    token_file: str = ".google_token"  # Path to save the token file
    scopes: list[str] = [
        "https://www.googleapis.com/auth/gmail.modify"
    ]  # Scopes to use when acquiring credentials
    include_spam_trash: bool = (
        False  # Include messages in Spam and Trash when searching for reports
    )
    oauth2_port: int = (
        8080  # The TCP port for the local server to listen on for the OAuth2 response
    )


## Microsoft Graph
## -----------------------------------------------------------------------------
class MicrosoftGraph(MailboxConnectionSource):
    """Source for connecting to Micosoft accounts using the Graph API"""

    config: MicrosoftGraphConfig

    def validate_config(self) -> None:
        if self.config.auth_method == "UsernamePassword":
            if self.config.username is None or self.config.password is None:
                raise ValueError("Must provide username and password")
        elif self.config.auth_method == "DeviceCode":
            if self.config.tenant_id is None:
                raise ValueError("Must provide tenant_id")
        elif self.config.auth_method == "ClientSecret":
            if self.config.tenant_id is None:
                raise ValueError("Must provide tenant_id")
        return

    def setup(self) -> None:
        super().setup()
        try:
            self.mailbox = mail.MSGraphConnection(
                auth_method=self.config.auth_method,
                mailbox=self.config.mailbox,
                client_id=self.config.client_id,
                client_secret=self.config.client_secret,
                username=self.config.username,
                password=self.config.password,
                tenant_id=self.config.tenant_id,
                token_file=self.config.token_file,
                allow_unencrypted_storage=self.config.allow_unencrypted_storage,
            )
        except Exception:
            self._state = SourceState.SETUP_ERROR
            raise

        self._state = SourceState.RUNNING
        return


class MicrosoftGraphConfig(MailboxConfig):
    auth_method: Literal["UsernamePassword", "DeviceCode", "ClientSecret"] = "UsernamePassword"
    client_id: str
    client_secret: str
    username: str | None = None
    password: str | None = None
    tenant_id: str | None = None
    mailbox: str | None = None
    token_file: str = ".microsoft_graph_token"
    allow_unencrypted_storage: bool = False
