from datetime import datetime
import time
import json
from json import JSONDecodeError
from invoke import Responder
from invoke.exceptions import UnexpectedExit
import requests
from paramiko.ssh_exception import AuthenticationException
from typing import Optional

from application.config.config import Config
from application.data.provider import upsert_many_provider, update_many_provider, get_all_providers
from application.data.system import update_system_detail
from application.exception.praetor_exception import PraetorException
from application.data.session import update_session_logs, update_provider_process_step, update_k8s_process_step,\
    get_chain_id, get_providers_session
from application.model.provider_process import ProviderProcess
from application.model.k8s_process import K8sProcess
from application.model.stage import Stage
from application.service.common import calculate_k8s_process, get_gpu_data
from application.utils.cache import load_object, cache_providers_list, delete_object
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def provider_services(ssh_client: SSHClient, session_id: str, domain_name: str, attributes: list,
                      wallet_address: str, persistent_type: str, per_unit_prices: dict,
                      k8s_process: Optional[bool] = False):
    error_step = {"step_name": Stage.PROVIDER_ERROR.name, "description": Stage.PROVIDER_ERROR.value, "percentage": -1}
    try:
        update_provider_process_step(session_id, _get_provider_step(ProviderProcess.PROVIDER_CHECK))
        if k8s_process is True:
            update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.PROVIDER_CHECK))

        # Create provider yaml file
        architecture = get_node_architecture(ssh_client)
        chain_id = get_chain_id(session_id)
        create_provider_file(ssh_client, wallet_address, domain_name, architecture, attributes,
                             persistent_type,  False, chain_id, session_id)

        update_provider_pricing_script(ssh_client, per_unit_prices)

        # Install the provider helm chart
        _install_provider_helm(ssh_client, session_id, k8s_process, chain_id)

        # Provider process completes
        time.sleep(5)
        update_provider_process_step(session_id, _get_provider_step(ProviderProcess.PROVIDER_PROCESS_COMPLETED))
        if k8s_process is True:
            update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.PROVIDER_PROCESS_COMPLETED))

        # Remove session from redis
        delete_object(session_id)

        return {"status": "success"}
    except AuthenticationException as ae:
        update_provider_process_step(session_id, error_step)
        raise ae
    except PraetorException as pe:
        update_provider_process_step(session_id, error_step)
        raise pe
    except UnexpectedExit as ue:
        update_provider_process_step(session_id, error_step)
        raise ue
    except Exception as e:
        update_provider_process_step(session_id, error_step)
        log.error(f"Error while creating provider for session id({session_id})- {e}")
        raise e


def create_provider_file(ssh_client: SSHClient, wallet_address: str, domain_name: str, architecture: str,
                         attributes: list, persistent_type: Optional[str], dashboard_process: bool,
                         chain_id: Optional[str], session_id: Optional[str]):
    try:
        log.info(f"Creating {Config.PROVIDER_CONFIG_FILENAME} file for akash")

        provider_config_file = f"{Config.PRAETOR_DIR}/{Config.PROVIDER_CONFIG_FILENAME}"
        node = Config.AKASH_NODE if chain_id == Config.CHAIN_ID else Config.AKASH_NODE_TESTNET
        gpu_process, gpu_type, gpu_model = get_gpu_data(session_id)
        persistent_attributes = ["capabilities/storage/1/class", "capabilities/storage/1/persistent",
                                 "capabilities/storage/2/class", "capabilities/storage/2/persistent"]
        gpu_attributes = [f"capabilities/gpu/vendor/{gpu_type}/model/{gpu_model}"]

        key_base64_result = ssh_client.run(f"cat {Config.PRAETOR_DIR}/key.pem | openssl base64 -A")
        key_secret_base64_result = ssh_client.run(f"cat {Config.PRAETOR_DIR}/key-pass.txt | openssl base64 -A")

        ssh_client.run(f"""
cat <<EOF | tee {provider_config_file}
from: {wallet_address}
key: {key_base64_result.stdout}
keysecret: {key_secret_base64_result.stdout}
domain: {domain_name}
node: {node}
gasprices: "0.035uakt"
gas: "auto"
gasadjustment: "1.6"
withdrawalperiod: 12h
attributes:
EOF
""")
        if dashboard_process is False:
            # Add Architecture attribute of Node
            attributes.append({"key": "arch", "value": architecture})

        for attribute in attributes:
            if attribute["key"] in persistent_attributes:
                persistent_attributes.remove(attribute["key"])
            if attribute["key"] in gpu_attributes:
                gpu_attributes.remove(attribute["key"])
            ssh_client.run(f"""
cat <<EOF | tee -a {provider_config_file}
    - key: {attribute["key"]}
      value: {attribute["value"]}
EOF
""")
        if persistent_type is not None:
            value = ""
            for persistent_attribute in persistent_attributes:
                if persistent_attribute == "capabilities/storage/1/class":
                    value = "default"
                if persistent_attribute == "capabilities/storage/1/persistent" or \
                        persistent_attribute == "capabilities/storage/2/persistent":
                    value = "true"
                if persistent_attribute == "capabilities/storage/2/class":
                    value = persistent_type
                ssh_client.run(f"""
cat <<EOF | tee -a {provider_config_file}
    - key: {persistent_attribute}
      value: {value}
EOF
""")
        if gpu_process is True:
            value = "true"
            for gpu_attribute in gpu_attributes:
                ssh_client.run(f"""
cat <<EOF | tee -a {provider_config_file}
    - key: {gpu_attribute}
      value: {value}
EOF
""")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def update_provider_domain(ssh_client: SSHClient, new_domain_name: str):
    try:
        provider_config_file = f"{Config.PRAETOR_DIR}/{Config.PROVIDER_CONFIG_FILENAME}"
        ssh_client.run(f"sed -i -E 's/^domain: .*/domain: {new_domain_name}/' {provider_config_file}")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def update_provider_pricing_script(ssh_client: SSHClient, per_unit_prices: dict):
    try:
        price_script = f"{Config.PRAETOR_DIR}/{Config.PRICE_SCRIPT_FILENAME}"

        download_new_price_script = False
        try:
            result = ssh_client.run(f"ls -la {price_script}")
            if "No such file or directory" in result.stdout:
                download_new_price_script = True
        except (AuthenticationException, UnexpectedExit) as e:
            download_new_price_script = True
            log.warn(f"Exception while reading price script - {e}")

        if download_new_price_script is True:
            log.info("Price script does not exist, downloading new price script from internet.")
            ssh_client.run(f"wget -O {price_script} {Config.PROVIDER_PRICE_SCRIPT_URL}")

        commands = [
            # Update if exists
            f"sed -i '/^PRICE_TARGET_CPU=/c\\PRICE_TARGET_CPU={per_unit_prices['cpu']}' {price_script}",
            f"sed -i '/^PRICE_TARGET_MEMORY=/c\\PRICE_TARGET_MEMORY={per_unit_prices['memory']}' {price_script}",
            f"sed -i '/^PRICE_TARGET_HD_EPHEMERAL=/c\\PRICE_TARGET_HD_EPHEMERAL={per_unit_prices['storage']}' {price_script}",
            f"sed -i '/^PRICE_TARGET_HD_PERS_HDD=/c\\PRICE_TARGET_HD_PERS_HDD={per_unit_prices['pres_hdd']}' {price_script}",
            f"sed -i '/^PRICE_TARGET_HD_PERS_SSD=/c\\PRICE_TARGET_HD_PERS_SSD={per_unit_prices['pres_ssd']}' {price_script}",
            f"sed -i '/^PRICE_TARGET_HD_PERS_NVME=/c\\PRICE_TARGET_HD_PERS_NVME={per_unit_prices['pres_nvme']}' {price_script}",
            f"sed -i '/^PRICE_TARGET_ENDPOINT=/c\\PRICE_TARGET_ENDPOINT={per_unit_prices['endpoint']}' {price_script}",
            f"sed -i '/^PRICE_TARGET_IP=/c\\PRICE_TARGET_IP={per_unit_prices['ip']}' {price_script}",
            f"""sed -i '/^PRICE_TARGET_GPU_MAPPINGS=/c\\PRICE_TARGET_GPU_MAPPINGS="*={per_unit_prices['gpu']}"' {price_script}""",

            # Insert if not exists
            f"grep -q '^PRICE_TARGET_CPU=' {price_script} || sed -i '17 i\\PRICE_TARGET_CPU={per_unit_prices['cpu']}' {price_script}",
            f"grep -q '^PRICE_TARGET_MEMORY=' {price_script} || sed -i '18 i\\PRICE_TARGET_MEMORY={per_unit_prices['memory']}' {price_script}",
            f"grep -q '^PRICE_TARGET_HD_EPHEMERAL=' {price_script} || sed -i '19 i\\PRICE_TARGET_HD_EPHEMERAL={per_unit_prices['storage']}' {price_script}",
            f"grep -q '^PRICE_TARGET_HD_PERS_HDD=' {price_script} || sed -i '20 i\\PRICE_TARGET_HD_PERS_HDD={per_unit_prices['pres_hdd']}' {price_script}",
            f"grep -q '^PRICE_TARGET_HD_PERS_SSD=' {price_script} || sed -i '21 i\\PRICE_TARGET_HD_PERS_SSD={per_unit_prices['pres_ssd']}' {price_script}",
            f"grep -q '^PRICE_TARGET_HD_PERS_NVME=' {price_script} || sed -i '22 i\\PRICE_TARGET_HD_PERS_NVME={per_unit_prices['pres_nvme']}' {price_script}",
            f"grep -q '^PRICE_TARGET_ENDPOINT=' {price_script} || sed -i '23 i\\PRICE_TARGET_ENDPOINT={per_unit_prices['endpoint']}' {price_script}",
            f"grep -q '^PRICE_TARGET_IP=' {price_script} || sed -i '24 i\\PRICE_TARGET_IP={per_unit_prices['ip']}' {price_script}",
            f"""grep -q '^PRICE_TARGET_GPU_MAPPINGS=' {price_script} || sed -i '25 i\\PRICE_TARGET_GPU_MAPPINGS="*={per_unit_prices['gpu']}"' {price_script}""",
        ]

        for command in commands:
            ssh_client.run(command)

        ssh_client.run(f"chmod +x {price_script}")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_provider_helm(ssh_client: SSHClient, session_id: str, k8s_process: bool, chain_id: Optional[str] = None):
    try:
        time.sleep(5)
        update_provider_process_step(session_id, _get_provider_step(ProviderProcess.INSTALL_PROVIDER_HELM))
        if k8s_process is True:
            update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.INSTALL_PROVIDER_HELM))

        crds_export = f"export CRDS='manifests.akash.network providerhosts.akash.network providerleasedips.akash.network'"
        try:
            ssh_client.run(f"{crds_export} && kubectl delete crd $CRDS")
        except UnexpectedExit as ue:
            error_message = ue.result.stderr
            log.info(f"Error from server while deleting crds: {error_message}")

        try:
            time.sleep(5)
            log.info("Applying akash network CRDs.")
            ssh_client.run(f"kubectl apply -f https://raw.githubusercontent.com/akash-network/provider/{Config.PROVIDER_SERVICES_VERSION_TESTNET}/pkg/apis/akash.network/crd.yaml")
        except UnexpectedExit as ue:
            error_message = ue.result.stderr
            log.info(f"Error from server while creating crds : {error_message}")

        try:
            ssh_client.run(f"""
cat <<EOF | tee {Config.PRAETOR_DIR}/crds.sh
for CRD in \$CRDS; do
kubectl annotate crd \$CRD helm.sh/resource-policy=keep
kubectl annotate crd \$CRD meta.helm.sh/release-name=akash-provider
kubectl annotate crd \$CRD meta.helm.sh/release-namespace=akash-services
kubectl label crd \$CRD app.kubernetes.io/managed-by=Helm
done
EOF
""")
            ssh_client.run(f"chmod +x {Config.PRAETOR_DIR}/crds.sh")
            ssh_client.run(f"{crds_export} && {Config.PRAETOR_DIR}/crds.sh")
        except UnexpectedExit as ue:
            error_message = ue.result.stderr
            log.info(f"Error from server while annotating and labeling crds : {error_message}")
        finally:
            ssh_client.run(f"rm -rf {Config.PRAETOR_DIR}/crds.sh")

        try:
            mainnet_provider_version = Config.PROVIDER_SERVICES_VERSION.lstrip('v')
            testnet_provider_version = Config.PROVIDER_SERVICES_VERSION_TESTNET.lstrip('v')
            image_tag = mainnet_provider_version if chain_id == Config.CHAIN_ID else testnet_provider_version

            price_script = f"{Config.PRAETOR_DIR}/{Config.PRICE_SCRIPT_FILENAME}"
            bid_price_script_output = ssh_client.run(f"cat {price_script} | openssl base64 -A")
            bid_price_script = bid_price_script_output.stdout

            ssh_client.run(f"helm install akash-provider akash/provider -n akash-services "
                           f"-f {Config.PRAETOR_DIR}/{Config.PROVIDER_CONFIG_FILENAME} --set chainid={chain_id} "
                           f"--set image.tag={image_tag} --set bidpricescript='{bid_price_script}'")
            log.info("Provider helm chart installed.")
        except UnexpectedExit as ue:
            error_message = ue.result.stderr
            log.info(f"Error from server while installing akash provider : {error_message}")

        # updated the session stage for given session id
        update_session_logs(session_id, f"Provider helm chart installed.")
    except AuthenticationException as ae:
        raise ae
    except Exception as e:
        raise e


def _get_provider_step(provider_enum: ProviderProcess):
    try:
        percentage = (provider_enum.values[1] / len(ProviderProcess)) * 100
        return {"step_name": provider_enum.name, "description": provider_enum.value, "percentage": round(percentage)}
    except Exception as e:
        raise e


def refresh_provider_list(is_testnet=False):
    try:
        # Determine network type and corresponding configurations
        network_type = "testnet" if is_testnet else "mainnet"
        chain_id = Config.CHAIN_ID_TESTNET if is_testnet else Config.CHAIN_ID
        cached_provider_list_name = Config.CACHED_PROVIDER_TESTNET_LIST_NAME if is_testnet else Config.CACHED_PROVIDER_LIST_NAME
        log.info(f"Fetching providers list from on-chain data for {network_type}...")

        # Load SSH client based on network type
        ssh_client = load_object(Config.APP_SESSION_ID_TESTNET if is_testnet else Config.APP_SESSION_ID)
        node_status = Config.AKASH_NODE_STATUS_CHECK_TESTNET if is_testnet else Config.AKASH_NODE_STATUS_CHECK

        # Execute command to fetch provider list
        cmd_result = ssh_client.run(
            f"~/bin/provider-services query provider list --node {node_status} --limit 800 -o json", hide=True
        )

        try:
            # Parse the fetched provider list
            provider_list = json.loads(cmd_result.stdout)
            log.info("Providers list fetched from on-chain.")
        except JSONDecodeError:
            log.error(f"Providers list is not a valid JSON object: {cmd_result.stdout}")
            raise PraetorException("Invalid request.", "P4042")

        # Upsert providers into the database
        providers = provider_list["providers"] if "providers" in provider_list else None
        providers_list = upsert_many_provider(providers, chain_id)

        # Get providers' status and update database
        providers_status = _get_providers_status(providers_list)
        update_many_provider(ssh_client, providers_status["data"], chain_id)

        # Update system details with the last updated timestamp
        field_name = "provider_list_updated_at" if not is_testnet else "provider_testnet_list_updated_at"
        update_system_detail(
            {"app_name": "praetor"},
            {"$set": {field_name: datetime.utcnow()}},
            True
        )

        # Cache the providers' list with a timestamp
        providers = get_all_providers(chain_id)
        providers["timestamp"] = datetime.utcnow()
        cache_providers_list(cached_provider_list_name, providers)

        log.info("Provider list refresh done.")
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _get_providers_status(providers: list):
    try:
        url = f"https://{Config.SECURITY_HOST}/providers"

        payload = {
            "providers": providers
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


def get_node_architecture(ssh_client: SSHClient):
    try:
        # Get Kubernetes Nodes
        result = ssh_client.run("kubectl get node -o json")
        node_details = json.loads(result.stdout)

        architecture = ""
        if "items" in node_details:
            items = node_details["items"]
            architecture = items[0]["status"]["nodeInfo"]["architecture"]

        return architecture
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def get_resources_from_nodes(ssh_client: SSHClient, session_id: str, nodes: list,
                             passphrase: Optional[str] = None, ssh_mode: Optional[str] = None,
                             control_machine_included: Optional[bool] = False):
    try:
        remote_key_file_path = f".praetor/id_rsa_{session_id}"
        cpu, memory, storage = 0, 0, 0
        if control_machine_included is True:
            cpu, memory, storage = get_control_machine_node_resources(ssh_client)

        # Get Nodes details
        for node in nodes:
            ip = node["ip"]
            username = node["username"]
            if ssh_mode == "password":
                # create input prompts for password for ssh connection
                password = node["password"]
                password_prompt = Responder(pattern=f"{username}@{ip}'s password:", response=f"{password}\n")
                ssh_command = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -q {username}@{ip} 'echo 2>&1'"

                # Get CPU details
                cpu_response = ssh_client.run(f"{ssh_command} && grep -c ^processor /proc/cpuinfo", pty=True,
                                              watchers=[password_prompt])
                cpu_response = cpu_response.stdout.replace("\r", "").replace("\n", "")
                cpu += int(cpu_response.strip())

                # Get Memory details
                memory_response = ssh_client.run(f"{ssh_command} && cat /proc/meminfo | grep MemAvailable", pty=True,
                                                 watchers=[password_prompt])
                memory_response = memory_response.stdout.replace("\r", "").replace("\n", "").lower()
                memory_response = memory_response.replace("memavailable:", "").replace("kb", "")
                memory += int(memory_response.strip()) * 1024

                # Get Storage details
                storage_response = ssh_client.run(f"{ssh_command} && df -h / --output=avail", pty=True,
                                                  watchers=[password_prompt])
                storage_response = storage_response.stdout.replace("\r", "").replace("\n", "").lower()
                storage_response = storage_response.replace("avail", "").replace("g", "")
                storage += float(storage_response.strip()) * 1073741824
            else:
                passphrase_prompt = Responder(pattern=f"Enter passphrase for key .*:",
                                              response=f"{passphrase}\n")
                ssh_command = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -q -i {remote_key_file_path} " \
                              f"{username}@{ip} 'echo 2>&1'"

                # Get CPU details
                cpu_response = ssh_client.run(f"{ssh_command} && grep -c ^processor /proc/cpuinfo", pty=True,
                                              watchers=[passphrase_prompt])
                cpu_response = cpu_response.stdout.replace("\r", "").replace("\n", "")
                cpu += int(cpu_response.strip())

                # Get Memory details
                memory_response = ssh_client.run(f"{ssh_command} && cat /proc/meminfo |grep MemAvailable", pty=True,
                                                 watchers=[passphrase_prompt])
                memory_response = memory_response.stdout.replace("\r", "").replace("\n", "").lower()
                memory_response = memory_response.replace("memavailable:", "").replace("kb", "")
                memory += int(memory_response.strip()) * 1024

                # Get Storage details
                storage_response = ssh_client.run(f"{ssh_command} && df -h / --output=avail", pty=True,
                                                  watchers=[passphrase_prompt])
                storage_response = storage_response.stdout.replace("\r", "").replace("\n", "").lower()
                storage_response = storage_response.replace("avail", "").replace("g", "")
                storage += float(storage_response.strip()) * 1073741824

        return {"cpu": cpu, "memory": memory, "storage": storage}
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def get_control_machine_node_resources(ssh_client: SSHClient):
    try:
        node_cpu = ssh_client.run("grep -c ^processor /proc/cpuinfo")
        node_cpu = node_cpu.stdout.replace("\r", "").replace("\n", "")
        cpu = int(node_cpu.strip())

        node_memory = ssh_client.run("cat /proc/meminfo | grep MemAvailable")
        node_memory = node_memory.stdout.replace("\r", "").replace("\n", "").lower()
        node_memory = node_memory.replace("memavailable:", "").replace("kb", "")
        memory = int(node_memory.strip()) * 1024

        node_storage = ssh_client.run("df -h / --output=avail")
        node_storage = node_storage.stdout.replace("\r", "").replace("\n", "").lower()
        node_storage = node_storage.replace("avail", "").replace("g", "")
        storage = float(node_storage.strip()) * 1073741824

        return cpu, memory, storage
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def get_resources_from_kube(ssh_client: SSHClient):
    try:
        # Get Kubernetes Nodes
        result = ssh_client.run("kubectl get node -o json")
        node_details = json.loads(result.stdout)

        cpu, memory, storage = 0, 0, 0
        if "items" in node_details:
            items = node_details["items"]
            for item in items:
                allocatable_cpu = item["status"]["allocatable"]["cpu"]
                if "m" in allocatable_cpu:
                    allocatable_cpu = int(allocatable_cpu.replace('m', ''))
                    cpu += allocatable_cpu / 1000
                else:
                    cpu += int(allocatable_cpu)

                allocatable_memory = item["status"]["allocatable"]["memory"]
                allocatable_memory = int(allocatable_memory.replace('Ki', ''))
                memory += allocatable_memory * 1024
                storage += int(item["status"]["allocatable"]["ephemeral-storage"])

        return {"cpu": cpu, "memory": memory, "storage": storage}
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def remove_providers_session():
    try:
        # Fetch providers sessions from database created on last 24 hours
        log.info(f"Fetching providers session list from database created on last 24 hours")

        sessions = get_providers_session()
        if len(sessions) > 0:
            for session in sessions:
                session_id = session["_id"]
                try:
                    delete_object(session_id)
                except Exception as e:
                    log.error(f"error while removing session ({session_id}) by cron with error - ({e})")
                    continue

        log.info(f"Provider sessions removed cron completed on ({datetime.now()}).")
    except Exception as e:
        raise e
