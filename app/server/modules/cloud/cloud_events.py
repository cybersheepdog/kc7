from app.server.modules.clock.Clock import Clock


class CloudSignInEvent:
    """
    Models a cloud identity-provider sign-in log (e.g. Microsoft Entra ID / AWS console).

    Used to simulate session-hijacking / token-theft "impossible travel": the same user
    and session_id appears from two geographically distant locations within a short window.

    All columns are strings (besides timestamp) to stay consistent with the other
    KC7 telemetry tables.
    """

    def __init__(self,
                 timestamp: float,
                 username: str,
                 application: str,
                 src_ip: str,
                 city: str,
                 country: str,
                 session_id: str,
                 result: str,
                 user_agent: str = "") -> None:

        self.timestamp = timestamp
        self.username = username
        self.application = application
        self.src_ip = src_ip
        self.city = city
        self.country = country
        self.session_id = session_id
        self.result = result
        self.user_agent = user_agent

    def stringify(self) -> dict:
        return {
            "timestamp": Clock.from_timestamp_to_string(self.timestamp),
            "username": self.username,
            "application": self.application,
            "src_ip": self.src_ip,
            "city": self.city,
            "country": self.country,
            "session_id": self.session_id,
            "result": self.result,
            "user_agent": self.user_agent,
        }

    @staticmethod
    def get_kql_repr() -> tuple:
        """Returns table:str, columns:dict"""
        return (
            "CloudSignInLogs",  # table name in KQL
            {
                "timestamp": "datetime",
                "username": "string",
                "application": "string",
                "src_ip": "string",
                "city": "string",
                "country": "string",
                "session_id": "string",
                "result": "string",
                "user_agent": "string",
            }
        )


class CloudStorageEvent:
    """
    Models a cloud storage audit / access log (e.g. AWS S3 / Azure Blob).

    Used to simulate exfiltration via storage: an adversary flips a bucket to be
    publicly accessible (a configuration change) and then a burst of object reads is
    served to external, unauthenticated IP addresses.

    operation examples:
      - "PutBucketAcl"   (config change making the bucket public)
      - "GetObject"      (object read / download)
    """

    def __init__(self,
                 timestamp: float,
                 operation: str,
                 bucket_name: str,
                 object_key: str,
                 requester_id: str,
                 requester_ip: str,
                 is_public: str,
                 bytes_transferred: str,
                 result: str) -> None:

        self.timestamp = timestamp
        self.operation = operation
        self.bucket_name = bucket_name
        self.object_key = object_key
        self.requester_id = requester_id
        self.requester_ip = requester_ip
        self.is_public = str(is_public)
        self.bytes_transferred = str(bytes_transferred)
        self.result = result

    def stringify(self) -> dict:
        return {
            "timestamp": Clock.from_timestamp_to_string(self.timestamp),
            "operation": self.operation,
            "bucket_name": self.bucket_name,
            "object_key": self.object_key,
            "requester_id": self.requester_id,
            "requester_ip": self.requester_ip,
            "is_public": self.is_public,
            "bytes_transferred": self.bytes_transferred,
            "result": self.result,
        }

    @staticmethod
    def get_kql_repr() -> tuple:
        """Returns table:str, columns:dict"""
        return (
            "CloudStorageLogs",  # table name in KQL
            {
                "timestamp": "datetime",
                "operation": "string",
                "bucket_name": "string",
                "object_key": "string",
                "requester_id": "string",
                "requester_ip": "string",
                "is_public": "string",
                "bytes_transferred": "string",
                "result": "string",
            }
        )
