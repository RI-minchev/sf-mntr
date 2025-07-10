from azure.storage.fileshare import ShareClient, ShareFileClient
from azure.core.exceptions import ResourceNotFoundError
import logging
from typing import Optional


class StateManager:
    """
    Azure File Share-based state manager for persisting and retrieving a marker (e.g., timestamp).
    Ensures share and file exist before operations.
    """

    def __init__(self, connection_string: str, share_name: str = 'funcstatemarkershare', file_path: str = 'funcstatemarkerfile'):
        self.file_path = file_path
        self.share_cli = ShareClient.from_connection_string(conn_str=connection_string, share_name=share_name)
        self.file_cli = ShareFileClient.from_connection_string(conn_str=connection_string, share_name=share_name, file_path=file_path)
        self._ensure_share_and_file()

    def _ensure_share_and_file(self):
        """Ensure the Azure File Share and file exist."""
        try:
            self.share_cli.get_share_properties()
        except ResourceNotFoundError:
            logging.info(f"Share '{self.share_cli.share_name}' not found. Creating it.")
            self.share_cli.create_share()
        try:
            self.file_cli.get_file_properties()
        except ResourceNotFoundError:
            logging.info(f"File '{self.file_path}' not found. Creating it.")
            self.file_cli.create_file(1024)  # 1KB initial size

    def post(self, marker_text: str) -> None:
        """
        Overwrite the file with the given marker_text.
        """
        logging.info(f'Saving time marker {self.file_path} - {marker_text}')
        data = marker_text.encode()
        try:
            self.file_cli.upload_file(data, overwrite=True)
        except ResourceNotFoundError:
            self._ensure_share_and_file()
            self.file_cli.upload_file(data, overwrite=True)

    def get(self) -> Optional[str]:
        """
        Retrieve the marker text from the file, or None if not found.
        """
        try:
            return self.file_cli.download_file().readall().decode()
        except ResourceNotFoundError:
            logging.info(f"File '{self.file_path}' not found when reading. Returning None.")
            return
