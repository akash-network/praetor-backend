import json
import requests
from fabric import Connection
from invoke.exceptions import UnexpectedExit, CommandTimedOut
from paramiko.ssh_exception import AuthenticationException

from application.data.session import update_session_logs, get_k8s_process_status_by_address, get_gpu_config
from application.config.config import Config
from application.exception.praetor_exception import PraetorException
from application.model.k8s_process import K8sProcess
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def get_operating_system(ssh_client: SSHClient):
    try:
        result_os = ssh_client.run("awk -F= '/^NAME/{print $2}' /etc/os-release")
        operating_system = result_os.stdout.rstrip("\n").replace('"', '')
        return operating_system
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def akash_provider_service_status_check(ssh_client: SSHClient):
    try:
        # check if the akash-provider service is running or not on the server
        result = ssh_client.run("systemctl is-active --quiet akash-provider && echo 'yes' || echo 'no'", True)
        if 'yes' in result.stdout:
            return True
        else:
            return False
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit:
        return False
    except Exception as e:
        raise e


def check_kube_connection(ssh_client: SSHClient):
    try:
        nodes_result = ssh_client.run("kubectl get nodes -o json")
        nodes = json.loads(nodes_result.stdout)
        if len(nodes["items"]) <= 0:
            return False
        else:
            items = nodes["items"]
            ready = False
            for item in items:
                taints = True if "taints" in item else False
                if taints is True:
                    ready = False
                    break
                else:
                    ready = True
            return ready
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit:
        return False
    except Exception as e:
        raise e


def check_on_chain_provider_status(ssh_client: SSHClient, wallet_address: str, chain_id: str):
    try:
        # Check Provider exist or not
        node = Config.AKASH_NODE_STATUS_CHECK if chain_id == Config.CHAIN_ID else Config.AKASH_NODE_STATUS_CHECK_TESTNET

        result = ssh_client.run(f"~/bin/provider-services query provider get {wallet_address} "
                                f"--node {node} --output json", timeout=30)
        provider_details = json.loads(result.stdout)
        return provider_details
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "address not found" in str(error_message):
            return False
        elif "unknown query path" in str(error_message):
            return False
        else:
            raise ue
    except Exception as e:
        raise e


def check_on_chain_provider_service_status(ssh_client: SSHClient, wallet_address: str, chain_id: str, hide: bool = False):
    try:
        node = Config.AKASH_NODE_STATUS_CHECK if chain_id == Config.CHAIN_ID else Config.AKASH_NODE_STATUS_CHECK_TESTNET

        result = ssh_client.run(f"~/bin/provider-services status {wallet_address} --node {node}", timeout=18, hide=hide)
        provider_details = json.loads(result.stdout)
        return provider_details
    except AuthenticationException as ae:
        raise ae
    except CommandTimedOut:
        return False
    except PraetorException as pe:
        raise pe
    except UnexpectedExit:
        return False
    except Exception as e:
        raise e


def get_passphrase(ssh_client: SSHClient):
    try:
        # get passphrase from the file to inject in subsequent command
        wallet_password_path = f"{Config.PRAETOR_DIR}/{Config.WALLET_PASSWORD_FILENAME}"
        password_result = ssh_client.run(f"cat {wallet_password_path}.txt", hide=True)

        return password_result.stdout
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def install_akash_software(ssh_client: SSHClient, session_id: str, chain_id: str):
    try:
        log.info(f"Installing akash software for session id ({session_id})")
        # check if akash command exist
        is_akash_exist = _akash_exist(ssh_client)
        if chain_id == Config.CHAIN_ID:
            akash_version = Config.AKASH_VERSION
            provider_services_version = Config.PROVIDER_SERVICES_VERSION
        else:
            akash_version = Config.AKASH_VERSION_TESTNET
            provider_services_version = Config.PROVIDER_SERVICES_VERSION_TESTNET

        if is_akash_exist is False:
            log.info("Akash software is not installed on the machine, installing...")
            # install akash software with the latest version
            ssh_client.run(f"curl https://raw.githubusercontent.com/akash-network/node/master/install.sh | "
                           f"bash -s -- {akash_version}")

            # install new akash provider services binary in bin folder along with akash binary
            ssh_client.run(f"curl https://raw.githubusercontent.com/akash-network/provider/main/install.sh | "
                           f"bash -s -- {provider_services_version}")

            update_session_logs(session_id, f"Akash software Installed.")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def install_akash_helm_repo(ssh_client: SSHClient, session_id: str):
    try:
        log.info(f"Installing akash helm repo for session id ({session_id})")

        ssh_client.run("helm repo remove akash")
        ssh_client.run("helm repo add akash https://akash-network.github.io/helm-charts")
        update_session_logs(session_id, f"Akash software Installed.")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "no repositories configured" in str(error_message) or "no repo named" in str(error_message):
            ssh_client.run("helm repo add akash https://akash-network.github.io/helm-charts")
            update_session_logs(session_id, f"Akash software Installed.")
        else:
            raise ue
    except Exception as e:
        raise e


def install_nvidia_k8s_device_plugin(ssh_client: SSHClient, session_id: str):
    try:
        log.info(f"Installing nvidia k8s device plugin helm repo for session id ({session_id})")

        ssh_client.run("helm repo remove nvdp")
        ssh_client.run("helm repo add nvdp https://nvidia.github.io/k8s-device-plugin")
        update_session_logs(session_id, f"NVIDIA k8s device plugin installed.")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "no repo named" in str(error_message):
            ssh_client.run("helm repo add nvdp https://nvidia.github.io/k8s-device-plugin")
            update_session_logs(session_id, f"NVIDIA k8s device plugin installed.")
        else:
            raise ue
    except Exception as e:
        raise e


def is_sudo_installed(connection: Connection):
    try:
        connection.run("sudo -V")
        return True
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "sudo: command not found" in str(error_message):
            return False
        else:
            raise ue
    except Exception as e:
        raise e


def is_sudo_password_allowed(connection: Connection, user_name: str):
    try:
        groups_output = connection.run(f"groups {user_name}")
        if "sudo" not in groups_output.stdout:
            return False

        connection.run("sudo -l")
        return True
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "sudo: a terminal is required to read the password" in str(error_message):
            return False
        else:
            raise ue
    except Exception as e:
        raise e


def _akash_exist(ssh_client: SSHClient):
    try:
        # Store Keyring Passphrase
        ssh_client.run(f"~/bin/akash version")
        ssh_client.run(f"~/bin/provider-services version")
        return True
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "No such file or directory" in str(error_message):
            return False
        else:
            raise ue
    except Exception as e:
        raise e


def get_active_process(wallet_address: str):
    try:
        return get_k8s_process_status_by_address(wallet_address)
    except Exception as e:
        raise e


def calculate_k8s_process(current_k8s_enum: K8sProcess):
    try:
        processes = []
        percentage = (current_k8s_enum.values[1] / len(K8sProcess)) * 100
        for k8s_enum in K8sProcess:
            status = "Completed" if k8s_enum.values[1] < current_k8s_enum.values[1] else "Pending"
            status = "Processing" if k8s_enum == current_k8s_enum else status
            status = "Completed" if current_k8s_enum.values[1] == len(K8sProcess) else status
            process = {
                "name": k8s_enum.values[0],
                "status": status
            }
            processes.append(process)

        return {"percentage": round(percentage), "processes": processes, "step_name": current_k8s_enum.name}
    except Exception as e:
        raise e


def akash_provider_version(host_uri: str):
    try:
        url = f"https://{Config.SECURITY_HOST}/providers/version"

        payload = {
            "provider_uri": host_uri
        }

        response = requests.request("POST", url, json=payload)
        if response.status_code == 200:
            return response.json()
        else:
            raise PraetorException(response.json(), "P50024")
    except PraetorException as pe:
        raise pe
    except Exception as e:
        raise e


def get_gpu_data(session_id: str):
    try:
        gpu_config = get_gpu_config(session_id)
        gpu_process, gpu_type, gpu_model = False, "nvidia", "t4"
        if gpu_config is not None:
            gpu_enabled, gpu_type, gpu_model = gpu_config["gpu"], gpu_config["type"], gpu_config["model"]
            if gpu_enabled is True and gpu_type == "nvidia":
                gpu_process = True

        return gpu_process, gpu_type, gpu_model
    except PraetorException as pe:
        raise pe
    except Exception as e:
        raise e


def compare_versions(version1, version2):
    try:
        version1 = version1.replace("v", "")
        version2 = version2.replace("v", "")

        def parse_version(version):
            version_parts = version.split('.')  # Split the version string by '.'
            version_ints = [int(part) for part in version_parts]  # Convert each part to an integer
            return version_ints

        # Parse the input version strings into lists of integers
        v1_parts = parse_version(version1)
        v2_parts = parse_version(version2)

        # Compare each part of the version numbers
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_num = v1_parts[i] if i < len(v1_parts) else 0  # Use 0 if no more parts in v1
            v2_num = v2_parts[i] if i < len(v2_parts) else 0  # Use 0 if no more parts in v2

            if v1_num < v2_num:
                return False  # version1 is smaller
            elif v1_num > v2_num:
                return True  # version2 is smaller

        return False  # Both versions are equal
    except Exception as e:
        raise e
