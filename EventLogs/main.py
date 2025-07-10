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

# Constants
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
    state_manager_logs = StateManager(FILE_SHARE_CONN_STRING, file_path='snowflake_logs')
    logging.info(f'State manager logs {state_manager_logs}')

    logs_date_from = parse_date_from(state_manager_logs.get())
    logging.info(f'Getting LOGS events from {logs_date_from}')
    last_ts = None

    move_stream_to_latest(ctx)
    for event in get_logs_events(ctx):
        sentinel.send(event)
        last_ts = event.get('timestamp')
        if last_ts:
            state_manager_logs.post(last_ts)
        if check_if_script_runs_too_long(script_start_time):
            logging.info(f'Script is running too long. Stop processing new events. Finish script. Sent events: {sentinel.successfull_sent_events_number}')
            break
    sentinel.flush()
    if last_ts:
        state_manager_logs.post(last_ts)
    if check_if_script_runs_too_long(script_start_time):
        logging.info(f'Script is running too long. Stop processing new events. Finish script. Sent events: {sentinel.successfull_sent_events_number}')
        return
    truncate_latest_events(ctx)
    ctx.close()
    logging.info(f'Script finished. Sent events: {sentinel.successfull_sent_events_number}')

def parse_date_from(date_from: Optional[str]) -> datetime.datetime:
    try:
        date_from = parse_datetime(date_from)
    except Exception:
        pass
    if not isinstance(date_from, datetime.datetime):
        date_from = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(minutes=5)
    return date_from

def move_stream_to_latest(ctx: snowflake.connector.SnowflakeConnection) -> None:
    with ctx.cursor(DictCursor) as cs:
        cs.execute("""
            insert into ADMIN.UTILS.LATEST_EVENT_LOGS 
            select
                current_account() as account_name,
                timestamp as EVENT_TIMESTAMP,
                trim(resource_attributes['snow.database.name'],'"') as database_name,
                trim(resource_attributes['snow.schema.name'],'"') as schema_name,
                trim(record['severity_text'],'"') as severity,
                trim(resource_attributes['snow.executable.name'],'"') as source_object,
                trim(value,'"') as message,
                trim(resource_attributes['snow.query.id'],'"') as query_id  
            from ADMIN.UTILS.EVENT_LOGGING_STREAM
            where
                record_type ilike any ('log', 'event')
                and record['severity_text'] ilike any ('warn','error','fatal')
            order by event_timestamp asc
        """)

def get_logs_events(ctx: snowflake.connector.SnowflakeConnection) -> Iterable[dict]:
    with ctx.cursor(DictCursor) as cs:
        cs.execute("""
            select * from ADMIN.UTILS.LATEST_EVENT_LOGS 
            order by event_timestamp asc
        """)
        for row in cs:
            yield parse_logs_event(row)

def parse_logs_event(event: dict) -> dict:
    if 'EVENT_TIMESTAMP' in event and isinstance(event['EVENT_TIMESTAMP'], datetime.datetime):
        event['EVENT_TIMESTAMP'] = event['EVENT_TIMESTAMP'].isoformat()
    event['source_table'] = 'EVENT_LOGGING'
    return event

def truncate_latest_events(ctx: snowflake.connector.SnowflakeConnection) -> None:
    with ctx.cursor(DictCursor) as cs:
        cs.execute("truncate table ADMIN.UTILS.LATEST_EVENT_LOGS")

def check_if_script_runs_too_long(script_start_time: int) -> bool:
    now = int(time.time())
    duration = now - script_start_time
    max_duration = int(MAX_SCRIPT_EXEC_TIME_MINUTES * 60 * 0.85)
    return duration > max_duration
