import json
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException

from application.config.config import Config
from application.data.session import update_installation_error
from application.exception.praetor_exception import PraetorException
from application.service.calculate_resources import calculate_provider_resources_v31
from application.service.common import check_on_chain_provider_status, check_on_chain_provider_service_status, \
    install_akash_software, install_akash_helm_repo
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def akash_installation(ssh_client: SSHClient, session_id: str, install_akash: bool, operating_system: str):
    try:
        update_installation_error(session_id, {"status": True, "description": "started"})
        # Update the package manager and install necessary dependencies using apt or yum based on operating system
        if operating_system == "Ubuntu" or operating_system == "Debian GNU/Linux":
            _install_apt_dependencies(ssh_client)
        elif operating_system == "CentOS Linux" or operating_system == "Amazon Linux":
            _install_yum_dependencies(ssh_client)
        else:
            raise PraetorException("Operating system is not supported.", "P5000")

        # Install helm
        _install_helm(ssh_client)

        # install akash software on the machine if not installed
        install_akash_software(ssh_client, session_id, Config.CHAIN_ID)

        # install akash helm repo on the machine if not installed
        install_akash_helm_repo(ssh_client, session_id)

        if install_akash is True:
            _make_akash_ready(ssh_client)

        update_installation_error(session_id, {"status": True, "description": "completed"})
    except AuthenticationException as ae:
        update_installation_error(session_id, {"status": False, "description": f"{ae}"})
        raise ae
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        update_installation_error(session_id, {"status": False, "description": f"{message}"})
        raise ue
    except Exception as e:
        update_installation_error(session_id, {"status": False, "description": f"{e}"})
        raise e


def get_provider_details(wallet_address: str, ssh_client: SSHClient, chainid: str):
    try:
        provider_details = check_on_chain_provider_service_status(ssh_client, wallet_address, chainid)
        provider_attributes = check_on_chain_provider_status(ssh_client, wallet_address, chainid)

        if provider_details is not False and (chainid == Config.CHAIN_ID or chainid == Config.CHAIN_ID_TESTNET):
            provider_obj = calculate_provider_resources_v31(provider_details["manifest"], provider_details["bidengine"],
                                                            provider_details["cluster"],
                                                            provider_details["cluster_public_hostname"])
            provider_obj["provider_attributes"] = provider_attributes
            return provider_obj
        else:
            raise PraetorException("Provider not online.", "P4040")
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_apt_dependencies(ssh_client: SSHClient):
    try:
        # update and upgrade the apt-get
        log.info(f"Installing apt dependencies")
        ssh_client.run("apt-get update", True)
        ssh_client.run("DEBIAN_FRONTEND=noninteractive apt-get upgrade -qy", True)

        # install necessary dependencies, e.g git
        ssh_client.run("apt-get install git wget unzip curl alsa-utils -y", True)
        log.info(f"Installed apt dependencies")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_yum_dependencies(ssh_client: SSHClient):
    try:
        # update the yum packages
        log.info(f"Installing yum dependencies")
        ssh_client.run("yum update -y", True)

        # install necessary dependencies, e.g git
        ssh_client.run("yum install git wget curl unzip alsa-utils -y", True)
        log.info(f"Installed yum dependencies")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_helm(ssh_client: SSHClient):
    try:
        log.info(f"Installing helm")

        # download and install helm
        ssh_client.run("curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash")

        log.info(f"Installed helm")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_common_dependencies(ssh_client: SSHClient):
    try:
        log.info(f"Installing common dependencies")

        # download and install helm
        ssh_client.run("curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash")
        #
        # # download the kubespray and remove the old kubespray directory if any exist
        # ssh_client.run("rm -rf ./kubespray/")
        # ssh_client.run("git clone https://github.com/kubernetes-sigs/kubespray.git")

        log.info(f"Installed common dependencies")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _make_akash_ready(ssh_client: SSHClient):
    try:
        # Label node1 as an ingress role
        log.info("Create label node1 as an ingress role")
        ssh_client.run(f"kubectl label --overwrite nodes node1 akash.network/role=ingress "
                       f"ingress-ready=true kubernetes.io/os=linux")

        # Create akash-service namespace
        ssh_client.run(f"kubectl create ns akash-services")
        ssh_client.run(f"kubectl label ns akash-services akash.network/name=akash-services akash.network=true")

        ssh_client.run(f"kubectl create ns lease")
        ssh_client.run(f"kubectl label ns lease akash.network=true")

        # Apply akash hostname operator service
        log.info("Apply akash hostname operator service")
        ssh_client.run(f"helm install akash-hostname-operator akash/akash-hostname-operator -n akash-services")

        log.info("Apply akash inventory operator service")
        ssh_client.run(f"helm upgrade --install inventory-operator akash/akash-inventory-operator -n akash-services")

        # Apply akash nginx ingress
        log.info("Apply akash nginx ingress")
        ssh_client.run(f"rm -rf ./ingress-nginx-custom.yaml")
        ssh_client.run(f"""
cat <<EOF | tee ingress-nginx-custom.yaml
controller:
  service:
    type: ClusterIP
  ingressClassResource:
    name: "akash-ingress-class"
  kind: DaemonSet
  hostPort:
    enabled: true
  admissionWebhooks:
    port: 7443
  config:
    allow-snippet-annotations: false
    enable-real-ip: true
    proxy-buffer-size: "16k"
  metrics:
    enabled: true
  extraArgs:
    enable-ssl-passthrough: true
tcp:
  "8443": "akash-services/akash-provider:8443"
  "8444": "akash-services/akash-provider:8444"
EOF
""")
        ssh_client.run(f"helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx")

        ssh_client.run(f"helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx --version 4.10.0 "
                       "--namespace ingress-nginx --create-namespace -f ingress-nginx-custom.yaml")

        ssh_client.run(f"kubectl label ns ingress-nginx app.kubernetes.io/name=ingress-nginx "
                       "app.kubernetes.io/instance=ingress-nginx")

        ssh_client.run("kubectl label ingressclass akash-ingress-class akash.network=true")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e
