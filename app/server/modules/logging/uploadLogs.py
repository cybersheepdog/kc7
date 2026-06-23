# Import external modules
from inspect import istraceback
from multiprocessing.dummy import Process
import pandas as pd
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.exceptions import KustoServiceError
from azure.kusto.data.helpers import dataframe_from_result_table
from azure.kusto.data.data_format import DataFormat
from azure.kusto.ingest import QueuedIngestClient, IngestionProperties, FileDescriptor, BlobDescriptor, ReportLevel, ReportMethod
from flask import current_app
from azure.kusto.data.helpers import dataframe_from_result_table

# Import internal modules
from app.server.modules.outbound_browsing.outboundEvent import OutboundEvent
from app.server.modules.endpoints.file_creation_event import FileCreationEvent
from app.server.modules.endpoints.processes import ProcessEvent
from app.server.modules.email.email import Email
from app.server.modules.infrastructure.DNSRecord import DNSRecord
from app.server.modules.organization.Company import Employee
from app.server.modules.authentication.authenticationEvent import AuthenticationEvent
from app.server.modules.inbound_browsing.inboundEvent import InboundBrowsingEvent
from app.server.modules.alerts.alerts import SecurityAlert
from app.server.modules.endpoints.security_event import SecurityEvent
from app.server.modules.cloud.cloud_events import CloudSignInEvent, CloudStorageEvent


class LogUploader():
    """
    Object allows us to upload data to azure
    Logs are batched and uploaded to their corresponding table after queue is full
    First: ingestion properties are read from the flaks config in Config.py

    see: https://github.com/Azure/azure-kusto-python/blob/master/azure-kusto-ingest/tests/sample.py
    """

    def __init__(self, queue_limit=1000):
        # Prefer DB-stored ADX config (set via admin GUI); fall back to config.py
        try:
            from app.server.models import ADXConfig
            adx_cfg = ADXConfig.query.get(1)
        except Exception:
            adx_cfg = None

        def _cfg(db_val, config_key):
            """Return DB value if set, otherwise fall back to app config."""
            if db_val and str(db_val).strip():
                return db_val.strip()
            return current_app.config.get(config_key, "")

        # set Azure tenant config variables
        self.AAD_TENANT_ID    = _cfg(adx_cfg.tenant_id    if adx_cfg else None, "AAD_TENANT_ID")
        self.KUSTO_URI        = _cfg(adx_cfg.cluster_uri  if adx_cfg else None, "KUSTO_URI")
        self.KUSTO_INGEST_URI = _cfg(adx_cfg.ingest_uri   if adx_cfg else None, "KUSTO_INGEST_URI")
        self.DATABASE         = _cfg(adx_cfg.database      if adx_cfg else None, "DATABASE")
        self.CUSTOM_TYPES = [
                                DNSRecord, Employee,
                                OutboundEvent, FileCreationEvent,
                                Email, AuthenticationEvent, InboundBrowsingEvent,
                                ProcessEvent, SecurityAlert,
                                SecurityEvent, CloudSignInEvent, CloudStorageEvent]

        # Authenticate with AAD application.
        self.client_id     = _cfg(adx_cfg.client_id     if adx_cfg else None, "CLIENT_ID")
        self.client_secret = _cfg(adx_cfg.client_secret if adx_cfg else None, "CLIENT_SECRET")

        # authentication for ingestion client
        kcsb_ingest = KustoConnectionStringBuilder.with_aad_application_key_authentication(self.KUSTO_INGEST_URI,
                                                                                           self.client_id, self.client_secret, self.AAD_TENANT_ID)

        # authentication for general client
        kcsb_data = KustoConnectionStringBuilder.with_aad_application_key_authentication(self.KUSTO_URI,
                                                                                         self.client_id, self.client_secret, self.AAD_TENANT_ID)

        self.ingest = QueuedIngestClient(kcsb_ingest)
        self.client = KustoClient(kcsb_data)

        # The queue will allow us to upload multiple rows at once
        # This allows the game to runs faster and enable us to make fewer API calls
        # self.queue will be in the format:
        # {
        #   "table_name": [dict, dict, dict],
        #   "table_name2": [dict, dict, dict]
        # }
        self.queue = {}
        # how many records do we hold until submitting everything to kusto
        self.queue_limit = queue_limit
        # running tally of rows sent per table over this uploader's life (#28 run-history)
        self.row_counts = {}
        # The singleton uploader's queue is shared across modules and read by the admin
        # progress poll while the generation thread writes; guard all queue/row-count
        # mutation so it stays consistent (#17). Reentrant so get_queue_length() can be
        # called from within send_request's locked section.
        self._lock = threading.RLock()
        # cap on concurrent per-table ingestions during a flush
        self._max_ingest_workers = 4

    def create_tables(self, reset: bool = False) -> None:
        """
        Create the tables that the logs will be uploaded to in Kusto
        """
        # Get KQL representation of each Class object
        drop_table_commands = []
        create_table_commands = []

        for custom_type in self.CUSTOM_TYPES:
            table_name, kql_repr = custom_type.get_kql_repr()
            command = LogUploader.create_table_command(table_name, kql_repr)
            create_table_commands.append(command)
            if reset:
                drop_table_commands.append(
                    f".drop table {table_name} ifexists"
                )

        # print("\n\n\n".join(drop_table_commands))
        # print("\n\n\n".join(create_table_commands))

        if current_app.config["ADX_DEBUG_MODE"]:
            # If ADX_DEBUG_MODE is enabled, return early
            # This will prevent creating tables on the ADX cluster
            return

        # Execute the Kql commands
        for command in (drop_table_commands + create_table_commands):
            response = self.client.execute_mgmt(self.DATABASE, command)
            print(response)

    @staticmethod
    def create_table_command(table_name: str, table_options: dict) -> str:
        """
        Take in a dictionary of options
        Generate texts required to create a new table in Kusto

        Input dict: {
            "time": "string",
            "method":"string",
            "scr_ip":"string",
            "user_agent":"string",
            "url", "string"
        }
        Example:
        create table ['OutboundBrowsingEvents']  
            (['time']:string, 
            ['method']:string, 
            ['src_ip']:string, 
            ['user_agent']:string, 
            ['url']:string)
        """

        kql_command = f".create table ['{table_name}']\n"
        command_parts = [f"['{col}']:{val_type}" for col,
                         val_type in table_options.items()]
        kql_command = kql_command + "(" + ",\n".join(command_parts) + ")"

        return kql_command

    @staticmethod
    def _create_user_permission_command(user_string:str, database: str) -> str:
        """
        Take a user string of the following format:
        aaduser=user@contoso.com
        msauser=user@outlook.com
        """
        # Does the user_string contain one of the required identifiers?
        if not any(prefix in user_string for prefix in ['aaduser=','msauser=']):
            raise Exception("ERROR: The user identifier must be prefixed by either aaduser= or msauser=")
        return f".add database {database} viewers ('{user_string}')"

    def get_user_permissions(self) -> list:
        """
        Get a list of user permissions from ADX
        """
        show_permissions_command = f".show database {self.DATABASE} principals | distinct PrincipalDisplayName"
        response = self.client.execute_mgmt(self.DATABASE, show_permissions_command)

        # Handle errors from Kusto Client
        if response.get_exceptions():
            raise response.get_exceptions()

        return dataframe_from_result_table(response.primary_results[0])['PrincipalDisplayName'].unique().tolist()

    def add_user_permissions(self, user_string: str) -> None:
        permission_command = LogUploader._create_user_permission_command(user_string, self.DATABASE)
        response = self.client.execute_mgmt(self.DATABASE, permission_command)
        # Raise any errors that come back from 
        if response.get_exceptions():
            raise response.get_exceptions()

    def get_queue_length(self):
        """
        Get the number of records stored in the queue
        this does a sum of lengths for lists under each tablename key
        """
        with self._lock:
            return sum(len(val) for val in self.queue.values())

    def row_counts_snapshot(self):
        """Thread-safe copy of the per-table row tally (read by the admin progress poll)."""
        with self._lock:
            return dict(self.row_counts)

    def send_request(self, data: dict, table_name: str) -> None:
        """
        Data is ingested as JSON
        convert to a pandas dataframe and upload to KUSTO
        """

        # put data in a dataframe for ingestion
        if isinstance(data, list):
            data = data[0]

        # Enqueue + decide whether to flush, all under the lock (#17). If we're flushing,
        # atomically SWAP the queue out and reset it inside the lock, then do the slow
        # Azure ingestion on the snapshot OUTSIDE the lock — so other threads can keep
        # enqueuing (no rows are lost during a flush, and writers don't block on HTTP).
        pending = None
        with self._lock:
            self.queue.setdefault(table_name, []).append(data)
            self.row_counts[table_name] = self.row_counts.get(table_name, 0) + 1
            if sum(len(v) for v in self.queue.values()) > self.queue_limit:
                pending = self.queue
                self.queue = {}

        if pending:
            # read the config flag here (in a thread that has the app context) so the
            # ingestion worker threads — which don't — never touch current_app.
            debug = bool(current_app.config.get("ADX_DEBUG_MODE"))
            self._flush(pending, debug)

    def _ingest_table(self, table_name, rows, debug):
        """Build a dataframe for one table and ingest it (one ADX call). Per-table, intact."""
        try:
            df = pd.DataFrame(rows)
            try:
                df = df.sort_values("timestamp", ascending=True)
            except Exception as e:
                print(f"failed to sort rows: {e}")
            if debug:
                print(f"[ADX_DEBUG] would upload {df.shape} to table {table_name}")
                return
            props = IngestionProperties(
                database=self.DATABASE, table=table_name,
                data_format=DataFormat.CSV, report_level=ReportLevel.FailuresAndSuccesses)
            result = self.ingest.ingest_from_dataframe(df, ingestion_properties=props)
            print(f"....added {df.shape} to azure for {table_name} table: {result}")
        except Exception as e:
            print(f"ingest error for {table_name}: {e}")

    def _flush(self, pending, debug):
        """
        Ingest a snapshot of the queue. Independent tables are ingested concurrently with a
        small thread pool so init isn't gated by sequential per-table Azure latency (#17);
        each table is still its own ingestion call. Falls back to serial in debug mode.
        """
        items = list(pending.items())
        if not items:
            return
        if debug or len(items) == 1:
            for tname, rows in items:
                self._ingest_table(tname, rows, debug)
            return
        workers = min(self._max_ingest_workers, len(items))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self._ingest_table, tname, rows, debug) for tname, rows in items]
            for f in futures:
                f.result()  # surface any worker exception / wait for completion