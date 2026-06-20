from app.server.modules.clock.Clock import Clock


class SecurityEvent:
    """
    A class that represents Windows Security/System event-log telemetry.

    A single table (SecurityEvents) is used to model the Windows event log so that
    several detection-worthy techniques share one queryable surface:

      - Event ID 4769  -> Kerberos service ticket request (Kerberoasting when RC4)
      - Event ID 7045  -> A new service was installed (PsExec lateral movement)
      - Event ID 1102  -> The audit/security log was cleared (defense evasion)
      - Event ID 104   -> A System event log was cleared (defense evasion)

    Columns are kept generic so they can describe any of the above. Fields that do
    not apply to a given event id are left as empty strings.

    All columns are typed as strings (besides timestamp) to stay consistent with the
    other KC7 telemetry tables, which avoid numeric column types for simpler ingestion.
    """

    def __init__(self,
                 timestamp: float,
                 event_id: str,
                 event_type: str,
                 hostname: str,
                 username: str,
                 src_ip: str = "",
                 target_server: str = "",
                 service_name: str = "",
                 ticket_encryption_type: str = "",
                 ticket_options: str = "",
                 logon_type: str = "",
                 details: str = "") -> None:

        self.timestamp = timestamp
        self.event_id = str(event_id)
        self.event_type = event_type
        self.hostname = hostname
        self.username = username
        self.src_ip = src_ip
        self.target_server = target_server
        self.service_name = service_name
        self.ticket_encryption_type = ticket_encryption_type
        self.ticket_options = ticket_options
        self.logon_type = logon_type
        self.details = details

    def stringify(self) -> dict:
        return {
            "timestamp": Clock.from_timestamp_to_string(self.timestamp),
            "event_id": self.event_id,
            "event_type": self.event_type,
            "hostname": self.hostname,
            "username": self.username,
            "src_ip": self.src_ip,
            "target_server": self.target_server,
            "service_name": self.service_name,
            "ticket_encryption_type": self.ticket_encryption_type,
            "ticket_options": self.ticket_options,
            "logon_type": self.logon_type,
            "details": self.details,
        }

    @staticmethod
    def get_kql_repr() -> tuple:
        """Returns table:str, columns:dict"""
        return (
            "SecurityEvents",  # table name in KQL
            {
                "timestamp": "datetime",
                "event_id": "string",
                "event_type": "string",
                "hostname": "string",
                "username": "string",
                "src_ip": "string",
                "target_server": "string",
                "service_name": "string",
                "ticket_encryption_type": "string",
                "ticket_options": "string",
                "logon_type": "string",
                "details": "string",
            }
        )
