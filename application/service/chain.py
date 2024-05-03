import json

from application.config.config import Config
from application.utils.ssh_client import SSHClient


def get_latest_block(ssh_client: SSHClient):
    try:
        akash_status_cmd = ssh_client.run(f"~/bin/akash status --node {Config.AKASH_NODE}")
        akash_status = json.loads(akash_status_cmd.stdout)
        latest_block = akash_status["SyncInfo"]["latest_block_height"]
        return latest_block
    except Exception as e:
        raise e
