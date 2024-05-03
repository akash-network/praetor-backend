import io

import fabric
import paramiko
from paramiko import PasswordRequiredException, SSHException
from typing import Optional
from application.exception.praetor_exception import PraetorException


class RemoteClient:
    # Client to interact with a remote host via SSH Key File & SCP.

    def __init__(self, host: str, port: int, user: str, password: Optional[str] = None, ssh_key: Optional[str] = None,
                 passphrase: Optional[str] = None, connect_timeout: Optional[int] = 20):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.ssh_key = ssh_key
        self.passphrase = passphrase
        self.connect_timeout = connect_timeout

    def connection(self):
        # Open connection to remote host.

        try:
            if self.password is not None:
                connection = fabric.Connection(self.host, self.user, self.port, connect_timeout=self.connect_timeout,
                                               connect_kwargs={"password": self.password},
                                               config=fabric.Config(overrides={"run": {"hide": False}}))
                return connection
            elif self.ssh_key is not None:
                p_key = paramiko.RSAKey.from_private_key(io.StringIO(self.ssh_key), self.passphrase)
                connection = fabric.Connection(self.host, self.user, self.port, connect_timeout=self.connect_timeout,
                                               connect_kwargs={"pkey": p_key},
                                               config=fabric.Config(overrides={"run": {"hide": False}}))
                return connection
        except PasswordRequiredException:
            raise PraetorException("The private key file is encrypted, and password is not given", "P5017")
        except SSHException:
            raise PraetorException("The key file is invalid", "P5018")
        except Exception as e:
            raise e
