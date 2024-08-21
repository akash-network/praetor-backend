from datetime import datetime
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException
import socket

from application.config.config import Config
from application.service.common import compare_versions
from application.data.provider import get_all_providers
from application.data.system import get_versions
from application.data.session import get_provider_request
from application.exception.praetor_exception import PraetorException
from application.service.provider import update_provider_pricing_script
from application.utils.cache import cache_providers_list
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def restart_provider_pod(ssh_client: SSHClient, chain_id: str):
    try:
        ssh_client.run(f"helm uninstall akash-provider -n akash-services")
        mainnet_provider_version = Config.PROVIDER_SERVICES_VERSION.lstrip('v')
        testnet_provider_version = Config.PROVIDER_SERVICES_VERSION_TESTNET.lstrip('v')

        image_tag = mainnet_provider_version if chain_id == Config.CHAIN_ID else testnet_provider_version
        price_script = f"{Config.PRAETOR_DIR}/{Config.PRICE_SCRIPT_FILENAME}"
        bid_price_script_output = ssh_client.run(f"cat {price_script} | openssl base64 -A")
        bid_price_script = bid_price_script_output.stdout
        try:
            ssh_client.run(f"helm install akash-provider akash/provider -n akash-services "
                           f"-f {Config.PRAETOR_DIR}/{Config.PROVIDER_CONFIG_FILENAME} --set chainid={chain_id} "
                           f"--set image.tag={image_tag} --set bidpricescript='{bid_price_script}'")

            ssh_client.run(
                f"kubectl -n akash-services get pods -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[*].image'")

            log.info("Provider helm chart installed.")
        except UnexpectedExit as ue:
            error_message = ue.result.stderr
            log.info(f"Error from server while installing akash provider : {error_message}")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def validate_provider_domain(control_machine_ip: str, provider_domain: str):
    valid_domain = False
    try:
        provider_ip = socket.gethostbyname(provider_domain)

        if provider_ip != control_machine_ip:
            return valid_domain

        valid_domain = True
        return valid_domain
    except AuthenticationException:
        return valid_domain
    except UnexpectedExit:
        return valid_domain
    except Exception:
        return valid_domain


def refresh_provider_list(chain_id):
    try:
        providers = get_all_providers(chain_id)
        providers["timestamp"] = datetime.utcnow()
        cache_providers_list(Config.CACHED_PROVIDER_LIST_NAME, providers)
    except Exception as e:
        raise e


def upgrade_provider_versions(ssh_client: SSHClient, session_id: str, provider_version: str,
                              chain_id: str, wallet_address: str):
    try:
        upgraded_version = provider_version
        log.info(f"Getting all versions from database")
        versions = get_versions(chain_id)
        if versions is not None:
            for version in versions:
                upgrade_required = compare_versions(version, provider_version)
                if upgrade_required is True:
                    method_name = f"upgrade_version_{version.replace('.', '').replace('-', '_')}"
                    method_exist = check_method_exist(method_name)
                    if method_exist is True:
                        method_name = globals()[method_name]
                        method_name(ssh_client, session_id, wallet_address)
                    upgraded_version = version

        return upgraded_version
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def check_method_exist(method_name: str):
    try:
        if method_name in globals():
            return True
        else:
            return False
    except Exception as e:
        raise e


def upgrade_version_v062(ssh_client: SSHClient, session_id: str, wallet_address: str):
    try:
        log.info(f"Start upgrading the provider version 0.6.2 for session_id: ({session_id})")

        log.info("Upgrade Provider service binary on the machine, installing...")
        # install new akash provider services binary in bin folder
        ssh_client.run(f"curl https://raw.githubusercontent.com/akash-network/provider/main/install.sh | bash -s -- v0.6.2")

        # Update helm repo
        ssh_client.run(f"helm repo update akash")
        # Backup chart values
        ssh_client.run("cd ~/.praetor && for i in $(helm list -n akash-services -q | grep -vw akash-node); do helm -n akash-services get values $i > ${i}.pre-v0.6.2.values; done")

        # Update charts
        ssh_client.run(f"helm -n akash-services upgrade akash-hostname-operator akash/akash-hostname-operator --reset-values")
        ssh_client.run(f"helm -n akash-services upgrade inventory-operator akash/akash-inventory-operator --reset-values")

        price_script = f"{Config.PRAETOR_DIR}/{Config.PRICE_SCRIPT_FILENAME}"
        old_price_script = f"{Config.PRAETOR_DIR}/{Config.PRICE_SCRIPT_FILENAME}.old"

        ssh_client.run(f"mv {price_script} {old_price_script}")

        # Update existing prices of provider
        provider_request = get_provider_request(session_id)

        bid_price_cpu_scale = provider_request["bid_price_cpu_scale"] \
            if "bid_price_cpu_scale" in provider_request else "1.6"
        bid_price_memory_scale = provider_request["bid_price_memory_scale"] \
            if "bid_price_memory_scale" in provider_request else "0.8"
        bid_price_storage_scale = provider_request["bid_price_storage_scale"] \
            if "bid_price_storage_scale" in provider_request else "0.02"
        bid_price_hd_pres_hdd_scale = provider_request["bid_price_hd_pres_hdd_scale"] \
            if "bid_price_hd_pres_hdd_scale" in provider_request else "0.01"
        bid_price_hd_pres_ssd_scale = provider_request["bid_price_hd_pres_ssd_scale"] \
            if "bid_price_hd_pres_ssd_scale" in provider_request else "0.03"
        bid_price_hd_pres_nvme_scale = provider_request["bid_price_hd_pres_nvme_scale"] \
            if "bid_price_hd_pres_nvme_scale" in provider_request else "0.04"
        bid_price_endpoint_scale = provider_request["bid_price_endpoint_scale"] \
            if "bid_price_endpoint_scale" in provider_request else "0.05"
        bid_price_ip_scale = provider_request["bid_price_ip_scale"] if "bid_price_ip_scale" in provider_request else "5"
        bid_price_gpu_scale = provider_request["bid_price_gpu_scale"] \
            if "bid_price_gpu_scale" in provider_request else "100"

        per_unit_prices = {
            "cpu": bid_price_cpu_scale,
            "memory": bid_price_memory_scale,
            "storage": bid_price_storage_scale,
            "pres_hdd": bid_price_hd_pres_hdd_scale,
            "pres_ssd": bid_price_hd_pres_ssd_scale,
            "pres_nvme": bid_price_hd_pres_nvme_scale,
            "endpoint": bid_price_endpoint_scale,
            "ip": bid_price_ip_scale,
            "gpu": bid_price_gpu_scale
        }

        update_provider_pricing_script(ssh_client, per_unit_prices)

        bid_price_script = ssh_client.run(f"cat {price_script} | openssl base64 -A")
        ssh_client.run(f"helm upgrade akash-provider akash/provider -n akash-services "
                       f"-f {Config.PRAETOR_DIR}/{Config.PROVIDER_CONFIG_FILENAME} "
                       f"--set chainid={Config.CHAIN_ID} --set image.tag=0.6.2 "
                       f"--set bidpricescript='{bid_price_script.stdout}' --reset-values")

        ssh_client.run(f"kubectl -n akash-services get pods -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[*].image' | grep -v akash-node")
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def upgrade_version_v064(ssh_client: SSHClient, session_id: str, wallet_address: str):
    try:
        log.info(f"Start upgrading the provider version 0.6.4 for session_id: ({session_id})")

        log.info("Upgrade Provider service binary on the machine, installing...")
        # install new akash provider services binary in bin folder
        ssh_client.run(f"curl https://raw.githubusercontent.com/akash-network/provider/main/install.sh | bash -s -- v0.6.4")

        # Update helm repo
        ssh_client.run(f"helm repo update akash")
        # Backup chart values
        ssh_client.run("cd ~/.praetor && for i in $(helm list -n akash-services -q | grep -vw akash-node); do helm -n akash-services get values $i > ${i}.pre-v0.6.4.values; done")

        # Update charts
        ssh_client.run(f"helm -n akash-services upgrade akash-hostname-operator akash/akash-hostname-operator --reset-values")
        ssh_client.run(f"helm -n akash-services upgrade inventory-operator akash/akash-inventory-operator --reset-values")

        price_script = f"{Config.PRAETOR_DIR}/{Config.PRICE_SCRIPT_FILENAME}"
        old_price_script = f"{Config.PRAETOR_DIR}/{Config.PRICE_SCRIPT_FILENAME}.old"

        ssh_client.run(f"mv {price_script} {old_price_script}")

        # Update existing prices of provider
        provider_request = get_provider_request(session_id)

        bid_price_cpu_scale = provider_request["bid_price_cpu_scale"] \
            if "bid_price_cpu_scale" in provider_request else "1.6"
        bid_price_memory_scale = provider_request["bid_price_memory_scale"] \
            if "bid_price_memory_scale" in provider_request else "0.8"
        bid_price_storage_scale = provider_request["bid_price_storage_scale"] \
            if "bid_price_storage_scale" in provider_request else "0.02"
        bid_price_hd_pres_hdd_scale = provider_request["bid_price_hd_pres_hdd_scale"] \
            if "bid_price_hd_pres_hdd_scale" in provider_request else "0.01"
        bid_price_hd_pres_ssd_scale = provider_request["bid_price_hd_pres_ssd_scale"] \
            if "bid_price_hd_pres_ssd_scale" in provider_request else "0.03"
        bid_price_hd_pres_nvme_scale = provider_request["bid_price_hd_pres_nvme_scale"] \
            if "bid_price_hd_pres_nvme_scale" in provider_request else "0.04"
        bid_price_endpoint_scale = provider_request["bid_price_endpoint_scale"] \
            if "bid_price_endpoint_scale" in provider_request else "0.05"
        bid_price_ip_scale = provider_request["bid_price_ip_scale"] if "bid_price_ip_scale" in provider_request else "5"
        bid_price_gpu_scale = provider_request["bid_price_gpu_scale"] \
            if "bid_price_gpu_scale" in provider_request else "100"

        per_unit_prices = {
            "cpu": bid_price_cpu_scale,
            "memory": bid_price_memory_scale,
            "storage": bid_price_storage_scale,
            "pres_hdd": bid_price_hd_pres_hdd_scale,
            "pres_ssd": bid_price_hd_pres_ssd_scale,
            "pres_nvme": bid_price_hd_pres_nvme_scale,
            "endpoint": bid_price_endpoint_scale,
            "ip": bid_price_ip_scale,
            "gpu": bid_price_gpu_scale
        }

        update_provider_pricing_script(ssh_client, per_unit_prices)

        bid_price_script = ssh_client.run(f"cat {price_script} | openssl base64 -A")
        ssh_client.run(f"helm upgrade akash-provider akash/provider -n akash-services "
                       f"-f {Config.PRAETOR_DIR}/{Config.PROVIDER_CONFIG_FILENAME} "
                       f"--set chainid={Config.CHAIN_ID} --set image.tag=0.6.4 "
                       f"--set bidpricescript='{bid_price_script.stdout}' --reset-values")

        ssh_client.run(f"kubectl -n akash-services get pods -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[*].image' | grep -v akash-node")
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_akash_helm_repo(ssh_client: SSHClient, session_id: str):
    try:
        log.info(f"Installing akash helm repo for session id ({session_id})")

        ssh_client.run("helm repo remove akash")
        ssh_client.run("helm repo add akash https://akash-network.github.io/helm-charts")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "no repositories configured" in str(error_message) or "no repo named" in str(error_message):
            ssh_client.run("helm repo add akash https://akash-network.github.io/helm-charts")
        else:
            raise ue
    except Exception as e:
        raise e


def install_latest_akash_provider_software(ssh_client: SSHClient, upgraded_version: str):
    try:
        # install new akash provider services binary in bin folder along with akash binary
        ssh_client.run(f"curl https://raw.githubusercontent.com/akash-network/provider/main/install.sh | "
                       f"sh -s -- {upgraded_version}")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def akash_provider_version_by_ssh(ssh_client: SSHClient):
    try:
        result = ssh_client.run(f"~/bin/provider-services version")
        provider_details = result.stderr.replace("\n", "")
        return provider_details if provider_details != "" else None
    except PraetorException:
        return None
    except UnexpectedExit:
        return None
    except Exception as e:
        raise e
