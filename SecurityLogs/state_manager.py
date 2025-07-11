from azure.storage.fileshare import ShareClient, ShareFileClient
from azure.core.exceptions import ResourceNotFoundError
import logging


class StateManager:
    def __init__(self, connection_string, share_name='funcstatemarkershare', file_path='funcstatemarkerfile'):
        self.file_path = file_path
        self.share_cli = ShareClient.from_connection_string(conn_str=connection_string, share_name=share_name)
        self.file_cli = ShareFileClient.from_connection_string(conn_str=connection_string, share_name=share_name, file_path=file_path)

    def post(self, marker_text: str):
        logging.info(f'Saving time marker {self.file_path} - {marker_text}')
        try:
            self.file_cli.upload_file(marker_text)
        except ResourceNotFoundError:
            self.share_cli.create_share()
            self.file_cli.upload_file(marker_text)

    def get(self):
        try:
            return self.file_cli.download_file().readall().decode()
        except ResourceNotFoundError:
            return None