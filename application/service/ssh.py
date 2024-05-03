import os
import traceback
from fabric import Connection
from invoke.exceptions import UnexpectedExit
from fabric.transfer import Transfer
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError
import socket
from typing import Optional

from application.config.config import Config
from application.data.session import update_session_stage, update_session_os, update_session_logs, \
    update_wallet_address, update_chain_id, update_provider_service_type
from application.exception.praetor_exception import PraetorException
from application.utils.remote_client import RemoteClient
from application.model.stage import Stage
from application.service.common import get_operating_system
from application.utils.cache import cache_object
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def create_ssh_connection(session_id: str, host: str, port: int, user: str, password: Optional[str] = None,
                          ssh_key: Optional[str] = None, passphrase: Optional[str] = None):
    try:
        valid_host = _validate_hostname(host)

        if valid_host is False:
            raise PraetorException("Hostname or IP address is incorrect.", "P5001")

        remote_client = RemoteClient(host=host, user=user, password=password, port=port, ssh_key=ssh_key,
                                     passphrase=passphrase, connect_timeout=20)

        # load remote client object in redis
        cache_object(session_id, remote_client)

        connection = remote_client.connection()
        log.info(f"remote client connection got created for host - {host}")
        return connection
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except socket.timeout as st:
        raise st
    except Exception as e:
        raise e


def create_rsa_key_pair(ssh_client: SSHClient, session_id: str, wallet_address: str, chain_id: str):
    try:
        algo = "rsa"
        praetor_ssh_dir = f"{Config.PRAETOR_DIR}"
        rsa_file_path = f"{Config.PRAETOR_DIR}/{Config.RSA_FILENAME}"
        bites_size = 2048

        # create ~/.ssh_praetor directory if not exist
        ssh_client.run(f"mkdir -p {praetor_ssh_dir}")

        # create ssh rsa key to encrypt and decrypt the subsequent data
        ssh_client.run(f"ssh-keygen -t {algo} -b {bites_size} -f {rsa_file_path} -N {session_id} -m PEM <<< y")
        ssh_client.run(f"ssh-keygen -f {rsa_file_path} -e -m pkcs8 > {rsa_file_path}.pem")
        result = ssh_client.run(f"cat {rsa_file_path}.pem")

        update_session_stage(session_id, Stage.NODE_VERIFIED)
        update_wallet_address(session_id, wallet_address)
        update_chain_id(session_id, chain_id)
        update_provider_service_type(session_id, "helm")
        update_session_logs(session_id, f"Public Key generated and RSA node verified.")

        return result.stdout
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def validate_operating_system(ssh_client: SSHClient, session_id: str):
    try:
        # get operating system for
        valid_operating_systems = ["Amazon Linux", "CentOS Linux", "Debian GNU/Linux", "Ubuntu"]

        operating_system = get_operating_system(ssh_client)
        if operating_system not in valid_operating_systems:
            raise PraetorException("Operating system is not supported.", "P5000")

        # Store Operating System in Database
        update_session_os(session_id, operating_system)
        return operating_system
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def validate_ssh_connection(connection: Connection):
    try:
        is_ssh_connected = _check_ssh_connection(connection)

        if is_ssh_connected is False:
            raise AuthenticationException
        return is_ssh_connected
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _validate_hostname(host: str):
    try:
        if socket.gethostbyname(host) == host:
            log.info(f"{host} is a valid IP address")
            return True
        elif socket.gethostbyname(host) != host:
            log.info(f"{host} is valid hostname")
            return True
    except socket.gaierror:
        log.error("{} is invalid hostname or IP address".format(host))
        return False


def _check_ssh_connection(connection: Connection):
    try:
        ls_command_result = connection.run("ls")
        if "Please login as the user" in ls_command_result.stdout:
            log.error(f"Login with the given user is not allowed. - {ls_command_result.stdout}")
            raise PraetorException("Login with the given user is not allowed.", "P5000")
        return True
    except AuthenticationException:
        return False
    except NoValidConnectionsError:
        return False
    except PraetorException as pe:
        raise pe


def configure_kubectl(ssh_client: SSHClient, session_id: str):
    try:
        # check if kube directory already exist, do not create
        ssh_client.run(f"[ -d {Config.KUBE_DIR} ] || mkdir {Config.KUBE_DIR}")

        # Copy Kubeconfig to the Provider
        transfer_instance = Transfer(ssh_client.connection)
        transfer_instance.put(f"{Config.UPLOAD_DIR}/{session_id}", f"{Config.KUBE_DIR}/config")
        # Remove file from Local Directory
        os.remove(f"{Config.UPLOAD_DIR}/{session_id}")

        # Install Kubectl on the Provider
        is_kubectl_exist = _kubectl_exist(ssh_client)
        if is_kubectl_exist is False:
            result = ssh_client.run("curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt")
            kube_ver = result.stdout

            googleapi_url = f"https://storage.googleapis.com/kubernetes-release/release/{kube_ver}/bin/linux/amd64/kubectl"
            ssh_client.run(f"curl -LO {googleapi_url}")

            ssh_client.run("chmod +x ./kubectl")
            ssh_client.run("mv ./kubectl /usr/local/bin/kubectl", True)

        # Verify Kubectl
        kube_connected = _check_kube_connection(ssh_client)
        if kube_connected is False:
            raise PraetorException("Kube files is not valid, Please upload valid file", "P5008")

        # updated the session stage for given session id
        update_session_stage(session_id, Stage.KUBE_CONFIGURED)
        update_session_logs(session_id, f"Kubectl Configured and verified.")
    except AuthenticationException as ae:
        raise ae
    except OSError as oe:
        raise oe
    except PraetorException as pe:
        raise pe
    except Exception as e:
        log.error(f"Error while configure kubectl - {traceback.format_exc()}")
        raise e


def _kubectl_exist(ssh_client: SSHClient):
    try:
        # Check kube file working or not
        ssh_client.run(f"kubectl --help")
        return True
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Error while running kubectl --help command - {error_message}")
        return False
    except Exception as e:
        raise e


def _check_kube_connection(ssh_client: SSHClient):
    try:
        # Check kube file working or not
        ssh_client.run(f"kubectl get nodes -o json")
        return True
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Error while running kubectl get nodes command - {error_message}")
        return False
    except Exception as e:
        raise e


def validate_system_language(ssh_client: SSHClient):
    try:
        # get system current language
        language = ssh_client.run("echo $LANG")

        if "C.UTF-8" in language.stdout or "en_" in language.stdout or "EN_" in language.stdout:
            return True
        else:
            return False
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Error while checking system language - {error_message}")
        raise ue
    except Exception as e:
        log.error(f"Error while checking system language - {e}")
        raise e

