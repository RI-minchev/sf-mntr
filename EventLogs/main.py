import snowflake.connector
from snowflake.connector import DictCursor
import datetime 
from typing import Iterable
from dateutil.parser import parse as parse_datetime
import logging
import os
import re
import time
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.primitives import serialization
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .sentinel_connector import AzureSentinelConnector
from .state_manager import StateManager


logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)
logging.getLogger('snowflake.connector').setLevel(logging.ERROR)

# Key Vault URL (replace with your Key Vault name)
KEY_VAULT_NAME = os.environ["KEY_VAULT"]
KEY_VAULT_URL = f"https://{KEY_VAULT_NAME}.vault.azure.net"

# Authenticate using Managed Identity
credential = DefaultAzureCredential()
client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

SNOWFLAKE_ACCOUNT = client.get_secret("SnowflakeAccount").value
SNOWFLAKE_USER = client.get_secret("SnowflakeUser").value
pem_str = client.get_secret("SnowflakePrivateKey").value
private_key = base64.b64decode(pem_str)
passphrase=client.get_secret("Passphrase").value.encode('utf-8')

p_key= serialization.load_pem_private_key(
    private_key,
    password=passphrase,
    backend=default_backend()
    )
SNOWFLAKE_PRIVATE_KEY = p_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())

WORKSPACE_ID = os.environ['WORKSPACE_ID']
SHARED_KEY = os.environ['SHARED_KEY']
FILE_SHARE_CONN_STRING = os.environ['AzureWebJobsStorage']
LOG_TYPE = 'Snowflake'

MAX_SCRIPT_EXEC_TIME_MINUTES = 5

LOG_ANALYTICS_URI = os.environ.get('logAnalyticsUri')

if not LOG_ANALYTICS_URI or str(LOG_ANALYTICS_URI).isspace():
    LOG_ANALYTICS_URI = 'https://' + WORKSPACE_ID + '.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern, str(LOG_ANALYTICS_URI))
if not match:
    raise Exception("Invalid Log Analytics Uri.")

def main(mytimer: func.TimerRequest):
    logging.info('Script started.')
    script_start_time = int(time.time())
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


    logs_date_from = state_manager_logs.get()
    logs_date_from = parse_date_from(logs_date_from)
    logging.info(f'Getting LOGS events from {logs_date_from}')
    last_ts = None
    for event in get_logs_events(ctx, logs_date_from):
        sentinel.send(event)
        last_ts = event.get('timestamp')
        if last_ts:
            state_manager_logs.post(last_ts)  # Update the state manager with the latest timestamp
        if check_if_script_runs_too_long(script_start_time):
            logging.info(f'Script is running too long. Stop processing new events. Finish script. Sent events: {sentinel.successfull_sent_events_number}')
            return
    sentinel.flush()
    if last_ts:
        state_manager_logs.post(last_ts)    

    if check_if_script_runs_too_long(script_start_time):
        logging.info(f'Script is running too long. Stop processing new events. Finish script. Sent events: {sentinel.successfull_sent_events_number}')
        return
    
    ctx.close()
    logging.info(f'Script finished. Sent events: {sentinel.successfull_sent_events_number}')


def parse_date_from(date_from: str) -> datetime.datetime:
    try:
        date_from = parse_datetime(date_from)
    except:
        pass
    if not isinstance(date_from, datetime.datetime):
        date_from = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - datetime.timedelta(minutes=15)
    return date_from


def get_logs_events(ctx: snowflake.connector.SnowflakeConnection, date_from: datetime.datetime) -> Iterable[dict]:
    cs = ctx.cursor(DictCursor)
    try:
        cs.execute(f"""select
                    current_account() as account_name,
                    timestamp as EVENT_TIMESTAMP,
                    trim(resource_attributes['snow.database.name'],'"') as database_name,
                    trim(resource_attributes['snow.schema.name'],'"') as schema_name,
                    trim(record['severity_text'],'"') as severity,
                    trim(resource_attributes['snow.executable.name'],'"') as source_object,
                    trim(value,'"') as message,
                    trim(resource_attributes['snow.query.id'],'"') as query_id  
                from admin.utils.event_logging where
                    record_type ilike any ('log', 'event') and
                    record['severity_text'] ilike any ('warn','error','fatal') and
                    timestamp > '{date_from.isoformat()}' 
                    order by event_timestamp asc""")
        for row in cs:
            row = parse_logs_event(row)
            yield row
    finally:
        cs.close()     


def parse_logs_event(event: dict) -> dict:
    if 'EVENT_TIMESTAMP' in event and isinstance(event['EVENT_TIMESTAMP'], datetime.datetime):
        event['EVENT_TIMESTAMP'] = event['EVENT_TIMESTAMP'].isoformat()
    event['source_table'] = 'EVENT_LOGGING'
    return event


def check_if_script_runs_too_long(script_start_time: int) -> bool:
        now = int(time.time())
        duration = now - script_start_time
        max_duration = int(MAX_SCRIPT_EXEC_TIME_MINUTES * 60 * 0.85)
        return duration > max_duration
