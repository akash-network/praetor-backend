from typing import Optional

from fabric import Connection
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException


class SSHClient:
    # Client to interact with a remote host via SSH Key File & SCP.

    def __init__(self, connection: Connection, sudo_user: bool = False):
        self.connection = connection
        self.sudo_user = sudo_user

    def run(self, command: str, sudo_command: Optional[bool] = False, **kwargs):
        # Execute command on remote host.

        try:
            if self.sudo_user is False:
                return self.connection.run(command, **kwargs)
            elif self.sudo_user is True and sudo_command is False:
                return self.connection.run(command, **kwargs)
            else:
                exec_command = f"sudo {command}".replace("sudo \n", "sudo ")
                return self.connection.run(f"{exec_command}", **kwargs)
        except AuthenticationException as ae:
            raise ae
        except UnexpectedExit as ue:
            raise ue
        except Exception as e:
            raise e
