"""
Embedded KQL console — Phase A (#52).

Runs a player's read-only KQL against the ADX ``SecurityLogs`` database so they can
investigate inside the app instead of the Azure portal. This executes player-supplied
queries with the app's credentials, so it is locked down on several layers:

  1. A least-privilege, viewer-only AAD principal (configure ``KQL_VIEWER_CLIENT_ID`` /
     ``KQL_VIEWER_CLIENT_SECRET``; falls back to the main principal if unset). This is the
     primary defense — the principal physically cannot mutate the cluster.
  2. ``validate_query`` (PURE, tested) rejects control/management commands (anything that
     starts with ``.``, including after a ``;``), cross-scope ``cluster()`` / ``database()``
     references, and the ``externaldata`` operator (which can fetch external URLs).
  3. Execution uses ``execute_query`` (never ``execute_mgmt``) — the query endpoint refuses
     control commands server-side regardless.
  4. Per-request caps: a server timeout and a hard row/size truncation, plus a per-player
     rate limit at the route layer.

The whole feature is gated behind ``EMBEDDED_KQL_ENABLED`` (default off).
"""

import re
import time


# Pre-compiled disallowed patterns (case-insensitive).
_CROSS_CLUSTER = re.compile(r"\bcluster\s*\(", re.IGNORECASE)
_CROSS_DB = re.compile(r"\bdatabase\s*\(", re.IGNORECASE)
_EXTERNAL = re.compile(r"\bexternaldata\b", re.IGNORECASE)


def validate_query(query: str, max_len: int = 20000):
    """
    PURE. Returns (ok: bool, reason: str). Allows only a single read-only KQL query.
    """
    if not query or not query.strip():
        return False, "Enter a query."
    if len(query) > max_len:
        return False, "Query is too long."

    if _CROSS_CLUSTER.search(query):
        return False, "cluster(...) is not allowed — you can only query this database."
    if _CROSS_DB.search(query):
        return False, "database(...) is not allowed — you can only query this database."
    if _EXTERNAL.search(query):
        return False, "externaldata is not allowed."

    # Control/management commands start with '.'. Split on statement separators (newlines
    # and ';') and check the first non-comment character of each segment, so a command
    # can't hide after a ';' or on a later line.
    for seg in re.split(r"[;\n]", query):
        s = seg.strip()
        if not s or s.startswith("//"):
            continue
        if s.startswith("."):
            return False, ("Control commands (starting with '.') are not allowed — "
                           "this console is read-only queries only.")
    return True, ""


def _timespan(seconds: int) -> str:
    seconds = max(1, int(seconds or 45))
    h, m, s = seconds // 3600, (seconds % 3600) // 60, seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def _resolve_adx_settings():
    """Cluster URI / tenant / database + the (viewer) principal, DB-config first then config.py."""
    from flask import current_app
    try:
        from app.server.models import ADXConfig
        cfg = ADXConfig.query.get(1)
    except Exception:
        cfg = None

    def pick(dbval, key):
        if dbval and str(dbval).strip():
            return str(dbval).strip()
        return current_app.config.get(key, "") or ""

    cluster = pick(cfg.cluster_uri if cfg else None, "KUSTO_URI")
    tenant = pick(cfg.tenant_id if cfg else None, "AAD_TENANT_ID")
    database = pick(cfg.database if cfg else None, "DATABASE")
    # Prefer a dedicated viewer-only principal; fall back to the main app principal.
    client_id = current_app.config.get("KQL_VIEWER_CLIENT_ID") or pick(cfg.client_id if cfg else None, "CLIENT_ID")
    client_secret = current_app.config.get("KQL_VIEWER_CLIENT_SECRET") or pick(cfg.client_secret if cfg else None, "CLIENT_SECRET")
    return cluster, tenant, database, client_id, client_secret


_CLIENT_CACHE = {"client": None, "db": None, "key": None}


def _get_client():
    """Build (and cache) a KustoClient for the configured viewer principal."""
    from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
    cluster, tenant, database, cid, csec = _resolve_adx_settings()
    if not (cluster and tenant and cid and csec and database):
        raise RuntimeError("ADX is not fully configured (cluster/tenant/principal/database).")
    key = (cluster, tenant, cid, database)
    if _CLIENT_CACHE["client"] is None or _CLIENT_CACHE["key"] != key:
        kcsb = KustoConnectionStringBuilder.with_aad_application_key_authentication(
            cluster, cid, csec, tenant)
        _CLIENT_CACHE["client"] = KustoClient(kcsb)
        _CLIENT_CACHE["db"] = database
        _CLIENT_CACHE["key"] = key
    return _CLIENT_CACHE["client"], _CLIENT_CACHE["db"]


def run_query(query: str):
    """
    IMPURE. Validate then execute a read-only query. Returns a dict:
      {ok, columns:[...], rows:[[...]], row_count, truncated, duration_ms}  on success
      {ok: False, error: str}                                              on failure
    """
    from flask import current_app
    from azure.kusto.data import ClientRequestProperties

    ok, reason = validate_query(query)
    if not ok:
        return {"ok": False, "error": reason}

    max_rows = int(current_app.config.get("EMBEDDED_KQL_MAX_ROWS", 5000) or 5000)
    timeout = int(current_app.config.get("EMBEDDED_KQL_TIMEOUT_SECONDS", 45) or 45)

    try:
        client, database = _get_client()
    except Exception as e:
        return {"ok": False, "error": "ADX not configured: " + str(e)}

    crp = ClientRequestProperties()
    try:
        crp.set_option("servertimeout", _timespan(timeout))
        crp.set_option("truncationmaxrecords", max_rows)
        crp.set_option("truncationmaxsize", 67108864)  # 64 MiB
    except Exception:
        pass

    started = time.time()
    try:
        # execute_query (not execute_mgmt): the query endpoint refuses control commands.
        resp = client.execute_query(database, query, crp)
    except Exception as e:
        return {"ok": False, "error": _clean_kusto_error(e)}
    duration_ms = int((time.time() - started) * 1000)

    try:
        table = resp.primary_results[0]
        columns = [c.column_name for c in table.columns]
        rows = []
        truncated = False
        for i, row in enumerate(table):
            if i >= max_rows:
                truncated = True
                break
            rows.append([_jsonsafe(row[c]) for c in columns])
        return {"ok": True, "columns": columns, "rows": rows,
                "row_count": len(rows), "truncated": truncated, "duration_ms": duration_ms}
    except Exception as e:
        return {"ok": False, "error": "Could not read results: " + str(e)}


def _jsonsafe(v):
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def _clean_kusto_error(e) -> str:
    msg = str(e)
    # Surface the human-readable bit of a Kusto error without the full stack/JSON.
    for marker in ("'@message':", "Message:", "message:"):
        if marker in msg:
            tail = msg.split(marker, 1)[1].strip().strip("'\"} ")
            if tail:
                return tail[:400]
    return msg[:400]


def get_schema():
    """
    Table + column schema for the console sidebar, derived from the app's own event
    classes (no ADX round-trip). Returns [{"table", "columns":[{"name","type"}...]}...].
    """
    from app.server.modules.infrastructure.DNSRecord import DNSRecord
    from app.server.modules.organization.Company import Employee
    from app.server.modules.outbound_browsing.outboundEvent import OutboundEvent
    from app.server.modules.endpoints.file_creation_event import FileCreationEvent
    from app.server.modules.email.email import Email
    from app.server.modules.authentication.authenticationEvent import AuthenticationEvent
    from app.server.modules.inbound_browsing.inboundEvent import InboundBrowsingEvent
    from app.server.modules.endpoints.processes import ProcessEvent
    from app.server.modules.alerts.alerts import SecurityAlert
    from app.server.modules.endpoints.security_event import SecurityEvent
    from app.server.modules.cloud.cloud_events import CloudSignInEvent, CloudStorageEvent

    classes = [DNSRecord, Employee, OutboundEvent, FileCreationEvent, Email,
               AuthenticationEvent, InboundBrowsingEvent, ProcessEvent, SecurityAlert,
               SecurityEvent, CloudSignInEvent, CloudStorageEvent]
    out = []
    for c in classes:
        try:
            name, cols = c.get_kql_repr()
            out.append({"table": name,
                        "columns": [{"name": k, "type": v} for k, v in cols.items()]})
        except Exception as e:
            print("kql schema: skipped", getattr(c, "__name__", c), "-", e)
    return sorted(out, key=lambda t: t["table"])
