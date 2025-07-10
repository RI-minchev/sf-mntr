import os
import re
import time
import base64
import logging
import datetime
from typing import Iterable, Optional

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dateutil.parser import parse as parse_datetime
import snowflake.connector
from snowflake.connector import DictCursor

from .sentinel_connector import AzureSentinelConnector
from .state_manager import StateManager

# Reduce noisy logs
logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)
logging.getLogger('snowflake.connector').setLevel(logging.ERROR)

LOG_TYPE = 'Snowflake'
MAX_SCRIPT_EXEC_TIME_MINUTES = 5

def get_secret_client() -> SecretClient:
    key_vault_name = os.environ["KEY_VAULT"]
    key_vault_url = f"https://{key_vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    return SecretClient(vault_url=key_vault_url, credential=credential)

def get_snowflake_private_key(client: SecretClient) -> bytes:
    pem_str = client.get_secret("SnowflakePrivateKey").value
    private_key = base64.b64decode(pem_str)
    passphrase = client.get_secret("Passphrase").value.encode('utf-8')
    p_key = serialization.load_pem_private_key(
        private_key,
        password=passphrase,
        backend=default_backend()
    )
    return p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def get_log_analytics_uri(workspace_id: str) -> str:
    uri = os.environ.get('logAnalyticsUri')
    if not uri or str(uri).isspace():
        uri = f'https://{workspace_id}.ods.opinsights.azure.com'
    pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
    if not re.match(pattern, str(uri)):
        raise Exception("Invalid Log Analytics Uri.")
    return uri

def main(mytimer: func.TimerRequest):
    logging.info('Script started.')
    script_start_time = int(time.time())

    client = get_secret_client()
    SNOWFLAKE_ACCOUNT = client.get_secret("SnowflakeAccount").value
    SNOWFLAKE_USER = client.get_secret("SnowflakeUser").value
    SNOWFLAKE_PRIVATE_KEY = get_snowflake_private_key(client)

    WORKSPACE_ID = os.environ['WORKSPACE_ID']
    SHARED_KEY = os.environ['SHARED_KEY']
    FILE_SHARE_CONN_STRING = os.environ['AzureWebJobsStorage']
    LOG_ANALYTICS_URI = get_log_analytics_uri(WORKSPACE_ID)

    ctx = snowflake.connector.connect(
        user=SNOWFLAKE_USER,
        private_key=SNOWFLAKE_PRIVATE_KEY,
        account=SNOWFLAKE_ACCOUNT
    )

    sentinel = AzureSentinelConnector(
        log_analytics_uri=LOG_ANALYTICS_URI,
        workspace_id=WORKSPACE_ID,
        shared_key=SHARED_KEY,
        log_type=LOG_TYPE,
        queue_size=1000
    )

    # State managers for each event type
    state_manager_logins = StateManager(FILE_SHARE_CONN_STRING, file_path='snowflake_logins')
    state_manager_queries = StateManager(FILE_SHARE_CONN_STRING, file_path='snowflake_queries')
    state_manager_rqueries = StateManager(FILE_SHARE_CONN_STRING, file_path='snowflake_rqueries')

    # LOGIN EVENTS
    process_events(
        ctx=ctx,
        sentinel=sentinel,
        state_manager=state_manager_logins,
        get_events_func=get_login_events,
        parse_event_func=parse_login_event,
        date_field='EVENT_TIMESTAMP',
        script_start_time=script_start_time,
        event_type='LOGIN'
    )

    # QUERY EVENTS
    process_events(
        ctx=ctx,
        sentinel=sentinel,
        state_manager=state_manager_queries,
        get_events_func=get_query_events,
        parse_event_func=parse_query_event,
        date_field='START_TIME',
        script_start_time=script_start_time,
        event_type='QUERY'
    )

    # READER QUERY EVENTS
    process_events(
        ctx=ctx,
        sentinel=sentinel,
        state_manager=state_manager_rqueries,
        get_events_func=get_reader_query_events,
        parse_event_func=parse_query_event,
        date_field='START_TIME',
        script_start_time=script_start_time,
        event_type='READER QUERY'
    )

    ctx.close()
    logging.info(f'Script finished. Sent events: {sentinel.successfull_sent_events_number}')

def process_events(
    ctx,
    sentinel,
    state_manager,
    get_events_func,
    parse_event_func,
    date_field: str,
    script_start_time: int,
    event_type: str
):
    date_from = state_manager.get()
    date_from = parse_date_from(date_from)
    logging.info(f'Getting {event_type} events from {date_from}')
    last_ts = None
    for event in get_events_func(ctx, date_from):
        event = parse_event_func(event)
        sentinel.send(event)
        last_ts = event.get(date_field)
        if sentinel.is_empty() and last_ts:
            state_manager.post(last_ts)
            if check_if_script_runs_too_long(script_start_time):
                logging.info(f'Script is running too long. Stop processing new events. Finish script. Sent events: {sentinel.successfull_sent_events_number}')
                return
    sentinel.flush()
    if last_ts:
        state_manager.post(last_ts)
    if check_if_script_runs_too_long(script_start_time):
        logging.info(f'Script is running too long. Stop processing new events. Finish script. Sent events: {sentinel.successfull_sent_events_number}')
        return

def parse_date_from(date_from: Optional[str]) -> datetime.datetime:
    try:
        date_from = parse_datetime(date_from)
    except Exception:
        pass
    if not isinstance(date_from, datetime.datetime):
        date_from = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(minutes=5)
    return date_from

def get_login_events(ctx: snowflake.connector.SnowflakeConnection, date_from: datetime.datetime) -> Iterable[dict]:
    with ctx.cursor(DictCursor) as cs:
        cs.execute(
            f"SELECT current_account() as account_name, * "
            f"FROM table(snowflake.information_schema.login_history(RESULT_LIMIT => 10000)) "
            f"WHERE EVENT_TIMESTAMP > '{date_from.isoformat()}' ORDER BY EVENT_TIMESTAMP ASC"
        )
        for row in cs:
            yield row

def get_query_events(ctx: snowflake.connector.SnowflakeConnection, date_from: datetime.datetime) -> Iterable[dict]:
    with ctx.cursor(DictCursor) as cs:
        cs.execute("USE SCHEMA snowflake.account_usage")
        cs.execute(
            f"SELECT current_account() as account_name, * FROM QUERY_HISTORY "
            f"WHERE START_TIME > '{date_from.isoformat()}' ORDER BY START_TIME ASC"
        )
        for row in cs:
            yield row

def get_reader_query_events(ctx: snowflake.connector.SnowflakeConnection, date_from: datetime.datetime) -> Iterable[dict]:
    with ctx.cursor(DictCursor) as cs:
        cs.execute("USE SCHEMA snowflake.reader_account_usage")
        cs.execute(
            f"SELECT current_account() as account_name, * FROM QUERY_HISTORY "
            f"WHERE START_TIME > '{date_from.isoformat()}' ORDER BY START_TIME ASC"
        )
        for row in cs:
            yield row

def parse_login_event(event: dict) -> dict:
    if 'EVENT_TIMESTAMP' in event and isinstance(event['EVENT_TIMESTAMP'], datetime.datetime):
        event['EVENT_TIMESTAMP'] = event['EVENT_TIMESTAMP'].isoformat()
    event['source_table'] = 'LOGIN_HISTORY'
    return event

def parse_query_event(event: dict) -> dict:
    if 'START_TIME' in event and isinstance(event['START_TIME'], datetime.datetime):
        event['START_TIME'] = event['START_TIME'].isoformat()
    if 'END_TIME' in event and isinstance(event['END_TIME'], datetime.datetime):
        event['END_TIME'] = event['END_TIME'].isoformat()
    event['source_table'] = 'QUERY_HISTORY'
    return event

def check_if_script_runs_too_long(script_start_time: int) -> bool:
    now = int(time.time())
    duration = now - script_start_time
    max_duration = int(MAX_SCRIPT_EXEC_TIME_MINUTES * 60 * 0.85)
    return duration > max_duration