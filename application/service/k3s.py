import time
from typing import Optional
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError

from application.config.config import Config
from application.model.stage import Stage
from application.model.k3s_process import K3sProcess
from application.exception.praetor_exception import PraetorException
from application.service.common import check_kube_connection, install_akash_software, install_akash_helm_repo, \
    install_nvidia_k8s_device_plugin
from application.data.session import update_k3s_process_step
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def k3s_installation(ssh_client: SSHClient, session_id: str, operating_system: str, chain_id: str,
                     gpu_enabled: Optional[bool] = False, gpu_type: Optional[str] = None,
                     gpu_model: Optional[str] = None):
    error_step = {"step_name": Stage.K3S_ERROR.name, "description": Stage.K3S_ERROR.value, "percentage": -1}
    k3s_installed = False
    try:
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.SYSTEM_CHECK))

        # Check k3s already installed or not
        kube_connected = check_kube_connection(ssh_client)
        if kube_connected is False:
            # Update the package manager and install necessary dependencies using apt or yum based on operating system
            if operating_system == "Ubuntu" or operating_system == "Debian GNU/Linux":
                _install_apt_dependencies(ssh_client, session_id)
            elif operating_system == "CentOS Linux" or operating_system == "Amazon Linux":
                _install_yum_dependencies(ssh_client, session_id)
            else:
                raise PraetorException("Operating system is not supported.", "P5000")

            # Install helm
            _install_helm(ssh_client, session_id)

            if gpu_enabled is True and gpu_type == "nvidia":
                # Install NVIDIA Drivers and Toolkit
                _install_nvidia_drivers_and_toolkit(ssh_client, session_id)

            # install akash software on the machine if not installed
            time.sleep(3)
            update_k3s_process_step(session_id, _get_provider_step(K3sProcess.AKASH_INSTALL))
            install_akash_software(ssh_client, session_id, chain_id)

            # install akash helm repo on the machine if not installed
            time.sleep(3)
            update_k3s_process_step(session_id, _get_provider_step(K3sProcess.AKASH_HELM_INSTALL))
            install_akash_helm_repo(ssh_client, session_id)

            # install NVIDIA k8s device plugin
            if gpu_enabled is True and gpu_type == "nvidia":
                time.sleep(3)
                update_k3s_process_step(session_id, _get_provider_step(K3sProcess.NVIDIA_HELM_INSTALL))
                install_nvidia_k8s_device_plugin(ssh_client, session_id)

            # Install K3S
            _install_k3s(ssh_client, session_id)
            k3s_installed = True

            # Copy kube config file
            _copy_configuration(ssh_client, session_id)

            # Making Akash Ready
            _make_akash_ready(ssh_client, session_id, chain_id, gpu_enabled, gpu_type, gpu_model)

        time.sleep(5)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.K3S_PROCESS_COMPLETED))
    except AuthenticationException as ae:
        update_k3s_process_step(session_id, error_step)
        _k3s_uninstall(ssh_client, k3s_installed)
        raise ae
    except PraetorException as pe:
        update_k3s_process_step(session_id, error_step)
        _k3s_uninstall(ssh_client, k3s_installed)
        raise pe
    except UnexpectedExit as ue:
        update_k3s_process_step(session_id, error_step)
        _k3s_uninstall(ssh_client, k3s_installed)
        raise ue
    except Exception as e:
        update_k3s_process_step(session_id, error_step)
        _k3s_uninstall(ssh_client, k3s_installed)
        raise e


def _install_apt_dependencies(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.DEPENDENCIES))

        # update and upgrade the apt-get
        log.info(f"Installing apt dependencies")
        ssh_client.run("apt-get update", True)
        ssh_client.run("DEBIAN_FRONTEND=noninteractive apt-get upgrade -qy", True)

        # install necessary dependencies, e.g git
        ssh_client.run("DEBIAN_FRONTEND=noninteractive apt-get install git wget unzip curl alsa-utils -qy", True)
        log.info(f"Installed apt dependencies")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_yum_dependencies(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.DEPENDENCIES))

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


def _install_helm(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.HELM_INSTALL))
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


def _check_nvidia_install_packages(ssh_client: SSHClient):
    packages = ["nvidia-cuda-toolkit", "nvidia-container-toolkit"]

    installation_packages = []
    for package in packages:
        # Check if package is installed
        try:
            result = ssh_client.run(f"dpkg -s {package}", True)
            if "Status: install ok installed" not in result.stdout:
                # Package is not installed, add installation command
                installation_packages.append(f"{package}")
        except UnexpectedExit:
            # An error occurred while checking the package status, assume package is not installed
            installation_packages.append(f"{package}")

    # Check if nvidia-container-runtime file is present
    try:
        result = ssh_client.run("ls /usr/bin/nvidia-container-runtime", True)
        if "No such file or directory" in result.stdout:
            # nvidia-container-runtime file is not present, add installation command
            installation_packages.append("nvidia-container-runtime")
    except UnexpectedExit:
        # An error occurred while checking the file, assume file is not present
        installation_packages.append("nvidia-container-runtime")

    return installation_packages


def _install_nvidia_drivers_and_toolkit(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.NVIDIA_INSTALL))
        log.info(f"Prepare Environment for NVIDIA")

        # Call the function to check packages and get installation commands
        installation_packages = _check_nvidia_install_packages(ssh_client)

        log.info(f"Installing packages, {installation_packages}")

        if len(installation_packages) > 0:
            # Perform system updates
            log.info("Performing system updates...")
            ssh_client.run(f"DEBIAN_FRONTEND=noninteractive apt -qy -o Dpkg::Options::='--force-confdef' "
                           f"-o Dpkg::Options::='--force-confold' dist-upgrade", True)
            ssh_client.run(f"apt autoremove -y", True)

            # reboot the server and sleep for 5 seconds
            try:
                ssh_client.run("reboot", True)
            except UnexpectedExit:
                log.info("Rebooting the server...")
                time.sleep(5)

            # Check if the server is back online
            max_retries = 120
            retry_count = 0
            while retry_count < max_retries:
                try:
                    ssh_client.run(f"echo 'Server is online'")
                    log.info("Server is back online.")
                    break
                except (NoValidConnectionsError, TimeoutError, EOFError, UnexpectedExit, Exception):
                    retry_count += 1
                    log.info(
                        f"Server is still offline. Retrying in 5 seconds... (Attempt {retry_count}/{max_retries})")
                    time.sleep(5)

            # Install Ubuntu drivers
            log.info("Installing Ubuntu drivers...")
            ssh_client.run(f"apt install ubuntu-drivers-common -y", True)
            ssh_client.run(f"ubuntu-drivers devices", True)
            ssh_client.run(f"ubuntu-drivers autoinstall", True)

            # Add NVIDIA container repository
            distribution_result = ssh_client.run(f". /etc/os-release;echo $ID$VERSION_ID")
            distribution = distribution_result.stdout.replace("\n", "").replace("\r", "").lower()
            if distribution not in ["ubuntu18.04", "ubuntu20.04", "ubuntu22.04", "debian10", "debian11"]:
                if distribution.startswith("ubuntu"):
                    distribution = "ubuntu22.04"
                elif distribution.startswith("debian"):
                    distribution = "debian11"
                else:
                    PraetorException("OS is not supported for nvidia drivers.")

            ssh_client.run("curl -s -L https://nvidia.github.io/libnvidia-container/gpgkey | sudo apt-key add -")
            ssh_client.run(
                f"curl -s -L https://nvidia.github.io/libnvidia-container/{distribution}/libnvidia-container.list"
                f" | sudo tee /etc/apt/sources.list.d/libnvidia-container.list")

            # Install the missing packages
            installation_package = " ".join(installation_packages)
            log.info("Installing NVIDIA packages...")
            ssh_client.run(f"apt-get update", True)
            ssh_client.run(f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -qy {installation_package}")

            # reboot the server and sleep for 5 seconds
            try:
                ssh_client.run("reboot", True)
            except UnexpectedExit:
                log.info("Rebooting the server...")
                time.sleep(5)

            # Check if the server is back online
            max_retries = 120
            retry_count = 0
            while retry_count < max_retries:
                try:
                    ssh_client.run(f"echo 'Server is online'")
                    log.info("Server is back online.")
                    break
                except (NoValidConnectionsError, TimeoutError, EOFError, UnexpectedExit, Exception):
                    retry_count += 1
                    log.info(
                        f"Server is still offline. Retrying in 5 seconds... (Attempt {retry_count}/{max_retries})")
                    time.sleep(5)

            log.info("Packages installed successfully.")
        else:
            log.info("All packages are already installed.")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_k3s(ssh_client: SSHClient, session_id: str):
    try:
        try_count = 1
        kube_connected = False

        time.sleep(5)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.K3S_INSTALL))

        log.info(f"Installing k3s")
        ssh_client.run("curl -sfL https://get.k3s.io | sh -s - --node-name node1 "
                       "--disable traefik --write-kubeconfig-mode 644")

        ssh_client.run("alias kubectl='k3s kubectl'")

        time.sleep(60)
        while try_count <= 10 and kube_connected is False:
            # Check K3S install
            log.info(f"trying to check kube connection. count: {try_count}")
            kube_connected = check_kube_connection(ssh_client)
            try_count += 1
            time.sleep(5)

        log.info(f"Installed k3s")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _make_akash_ready(ssh_client: SSHClient, session_id: str, chain_id: str,
                      gpu_enabled: Optional[bool] = False, gpu_type: Optional[str] = None,
                      gpu_model: Optional[str] = None):
    try:
        # Label node1 as an ingress role
        time.sleep(15)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.NODE_LABEL))
        log.info("Create label node1 as an ingress role")
        ssh_client.run(f"kubectl label --overwrite nodes node1 akash.network/role=ingress "
                       f"ingress-ready=true kubernetes.io/os=linux")

        # Create akash-service namespace
        time.sleep(3)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.NAMESPACE_CREATE))
        ssh_client.run(f"kubectl create ns akash-services")
        ssh_client.run(f"kubectl label ns akash-services akash.network/name=akash-services akash.network=true")

        ssh_client.run(f"kubectl create ns lease")
        ssh_client.run(f"kubectl label ns lease akash.network=true")

        # Apply akash hostname operator service
        time.sleep(3)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.HOSTNAME_CREATE))
        log.info("Apply akash hostname operator service")
        mainnet_provider_version = Config.PROVIDER_SERVICES_VERSION.lstrip('v')
        testnet_provider_version = Config.PROVIDER_SERVICES_VERSION_TESTNET.lstrip('v')
        image_tag = mainnet_provider_version if chain_id == Config.CHAIN_ID else testnet_provider_version
        ssh_client.run(f"helm install akash-hostname-operator akash/akash-hostname-operator -n akash-services "
                       f"--set image.tag={image_tag}")

        log.info("Apply akash inventory operator service")
        ssh_client.run(f"helm upgrade --install inventory-operator akash/akash-inventory-operator -n akash-services "
                       f"--set image.tag={image_tag}")

        # Apply akash nginx ingress
        time.sleep(3)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.INGRESS_CREATE))
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

        # Apply NVIDIA Runtime Engine
        if gpu_enabled is True and gpu_type == "nvidia":
            time.sleep(3)
            log.info("Labeling node1 with gpu vendor and gpu model")
            ssh_client.run(f"kubectl label --overwrite node node1 "
                           f"akash.network/capabilities.gpu.vendor.{gpu_type}.model.{gpu_model}=true "
                           f"allow-nvdp=true")

            log.info("Create runtime class for nvidia")
            update_k3s_process_step(session_id, _get_provider_step(K3sProcess.CREATE_NVIDIA_RUNTIME_CLASS))
            ssh_client.run(f"""
cat <<'EOF' | kubectl apply -f -
kind: RuntimeClass
apiVersion: node.k8s.io/v1
metadata:
  name: nvidia
handler: nvidia
EOF
""")

            ssh_client.run(f"helm upgrade -i nvdp nvdp/nvidia-device-plugin --namespace nvidia-device-plugin "
                           f"--create-namespace --version 0.14.5 --set runtimeClassName='nvidia' "
                           f"--set deviceListStrategy=volume-mounts --set-string nodeSelector.allow-nvdp='true'")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _copy_configuration(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k3s_process_step(session_id, _get_provider_step(K3sProcess.COPY_CONFIG))

        # Copy kube config file
        log.info("Copy kube config file")
        ssh_client.run("cp /etc/rancher/k3s/k3s.yaml ~/.kube/config")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _get_provider_step(k3s_enum: K3sProcess):
    try:
        percentage = (k3s_enum.values[1] / len(K3sProcess)) * 100
        return {"step_name": k3s_enum.name, "description": k3s_enum.value, "percentage": round(percentage)}
    except Exception as e:
        raise e


def _k3s_uninstall(ssh_client: SSHClient, k3s_installed):
    try:
        if k3s_installed:
            ssh_client.run("/usr/local/bin/k3s-uninstall.sh")
    except Exception as e:
        raise e
