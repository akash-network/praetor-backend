import os
import shutil
from fastapi import UploadFile
from fabric.transfer import Transfer
import ipaddress
from invoke import Responder
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError
from typing import Optional
import time

from application.config.config import Config
from application.data.session import update_k8s_process_step, update_master_node, get_master_node, \
    update_ip_addresses, get_master_node_ip_addresses, update_installation_error, update_k8s_process_step_error, \
    update_nodes, get_persistent_storage_enable, get_ip_addresses
from application.exception.praetor_exception import PraetorException
from application.model.k8s_process import K8sProcess
from application.service.common import install_akash_software, calculate_k8s_process, install_akash_helm_repo, \
    install_nvidia_k8s_device_plugin, get_gpu_data, compare_versions
from application.service.persistent_storage import setup_persistent_storage
from application.service.provider import provider_services
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def k8s_installation(ssh_client: SSHClient, session_id: str, operating_system: str, chain_id: str):
    try:
        update_installation_error(session_id, {"status": True, "description": "started"})
        # Update the package manager and install necessary dependencies using apt or yum based on operating system
        if operating_system == "Ubuntu" or operating_system == "Debian GNU/Linux":
            _install_apt_dependencies(ssh_client)
        elif operating_system == "CentOS Linux" or operating_system == "Amazon Linux":
            _install_yum_dependencies(ssh_client)
        else:
            raise PraetorException("Operating system is not supported.", "P5000")
        _install_common_dependencies(ssh_client)

        install_akash_software(ssh_client, session_id, chain_id)

        # install akash helm repo on the machine if not installed
        install_akash_helm_repo(ssh_client, session_id)

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


def _install_apt_dependencies(ssh_client: SSHClient):
    try:
        log.info(f"Installing apt dependencies")

        # update and upgrade the apt-get
        ssh_client.run("apt-get update", True)
        ssh_client.run("DEBIAN_FRONTEND=noninteractive apt-get upgrade -qy", True)

        # install necessary dependencies, e.g git, wget, unzip, curl, sshpass
        ssh_client.run("apt-get install -y git wget unzip curl python3-pip sshpass alsa-utils software-properties-common", True)
        ssh_client.run("apt install libffi-dev", True)

        log.info(f"Installed apt dependencies")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_yum_dependencies(ssh_client: SSHClient):
    try:
        log.info(f"Installing yum dependencies")

        # update the yum packages
        ssh_client.run("yum update -y", True)

        # install necessary dependencies, e.g git, sshpass, libffi, curl, wget, unzip
        ssh_client.run("yum install epel-release", True)
        ssh_client.run(f"yum install python3-pip git sshpass software-properties-common libffi libffi-devel "
                       f"wget curl unzip alsa-utils -y", True)

        log.info(f"Installed yum dependencies")
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

        # download the kubespray and remove the old kubespray directory if any exist
        ssh_client.run("rm -rf ./kubespray/")
        ssh_client.run("git clone https://github.com/kubernetes-sigs/kubespray.git")

        log.info(f"Installed common dependencies")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def validate_nodes_connection(ssh_client: SSHClient, nodes: list, session_id: str,
                              key_file: Optional[UploadFile] = None, passphrase: Optional[str] = None,
                              control_machine_included: Optional[bool] = False):
    status = True
    node_connection = []
    nodes_list = []

    local_key_file_path = f"{Config.UPLOAD_DIR}/keyfile/{session_id}.pem"
    remote_key_file_path = f".praetor/id_rsa_{session_id}"

    local_private_ip = _get_private_ip(ssh_client) if control_machine_included is True else None
    try:
        if control_machine_included is True and local_private_ip is None:
            raise PraetorException("Not able to find private ip for selected nodes.", "P5091")
        if key_file is not None:
            ssh_mode = "file"
            ssh_client.run(f"rm -rf {remote_key_file_path} {remote_key_file_path}.pub")

            # Upload key file and move in physical location if available and check
            log.info(f"Getting key file with the name, {key_file.filename}")
            with open(f"{local_key_file_path}", "wb") as keyfile:
                shutil.copyfileobj(key_file.file, keyfile)

            # move the keyfile to the remote server
            transfer_instance = Transfer(ssh_client.connection)
            transfer_instance.put(f"{local_key_file_path}", f"{remote_key_file_path}")

            # change the permission on remote keyfile
            ssh_client.run(f"chmod 400 {remote_key_file_path}")
        else:
            ssh_mode = "password"

            hostname_cmd = ssh_client.run("hostname")
            hostname = hostname_cmd.stdout.replace("\n", "")
            ssh_client.run(f"ssh-keygen -t rsa -C {hostname} -f '{remote_key_file_path}' -P ''")

        master_username, ips = "", ""
        for x, node in enumerate(nodes):
            ip = node["ip"] if "ip" in node else PraetorException("IP must not be empty", "P50020")
            if local_private_ip is not None and ip == local_private_ip:
                continue
            ips = ips + f" {ip}"

            username = node["username"] if "username" in node \
                else PraetorException("Username must not be empty", "P50021")
            if x == 0:
                master_username = username

            password = node["password"] if "password" in node else None
            if password is None and ssh_mode == "password":
                PraetorException("Password must not be empty", "P50022")

            connected = True
            ip_address = ipaddress.ip_address(ip)
            if ip_address.is_global is True or ip_address.version == "6":
                status = False
                node_connection.append({"ip": ip, "username": username, "connected": False})
                continue
            try:
                if ssh_mode == "password":
                    # create input prompts for password for ssh connection
                    password_prompt = Responder(pattern=f"{username}@{ip}'s password:", response=f"{password}\n")
                    response = ssh_client.run(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -q {username}@{ip} "
                                              f"'echo 2>&1' && echo 'Connected' || echo 'Not-Connected'",
                                              pty=True, watchers=[password_prompt])
                    ssh_client.run(f"sshpass -p {password} ssh-copy-id -i {remote_key_file_path}.pub {username}@{ip}")
                else:
                    passphrase_prompt = Responder(pattern=f"Enter passphrase for key .*:",
                                                  response=f"{passphrase}\n")
                    response = ssh_client.run(f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -q -i "
                                              f"{remote_key_file_path} {username}@{ip} "
                                              f"'echo 2>&1' && echo 'connected' || echo 'not-connected'",
                                              pty=True, watchers=[passphrase_prompt])

                if "not-connected" in response.stdout.replace("\r", "").replace("\n", "").lower():
                    status = False
                    connected = False
            except UnexpectedExit as ue:
                message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
                log.error(f"Node connection error for IP: {ip} and message: {message}")
                status = False
                connected = False

            nodes_list.append({"ip": ip, "username": username})
            node_connection.append({"ip": ip, "username": username, "connected": connected})

        if control_machine_included is True and local_private_ip is not None:
            if ssh_mode == "password":
                ssh_client.run(f"cat {remote_key_file_path}.pub >> .ssh/authorized_keys")
            ips = f"{local_private_ip}" + ips
            master_username = ssh_client.connection.user
            nodes_list.insert(0, {"ip": local_private_ip, "username": master_username})

        ips = ips.lstrip()
        update_ip_addresses(session_id, ips)
        update_nodes(session_id, nodes_list)

        master_ip = ips.split(" ")[0]
        ingress_public_ip = _get_ingress_public_ip(ssh_client, session_id, master_ip, master_username)
        update_master_node(session_id, {"ip": master_ip, "user_name": master_username, "public_ip": ingress_public_ip})

        log.info(f"k8s nodes connection result - {node_connection}")
        return node_connection, status, ingress_public_ip
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e
    finally:
        # Remove key file from local directory
        if key_file is not None:
            os.remove(f"{local_key_file_path}")


def _get_private_ip(ssh_client: SSHClient):
    try:
        pri_address = None
        private_ip_cmd = ssh_client.run("ip route get 1.2.3.4 | awk '{print $7}'")
        private_ip = private_ip_cmd.stdout.replace("\n", "")

        ip_address = ipaddress.ip_address(private_ip)
        if ip_address.is_global is True or ip_address.version == "6":
            private_ip_cmd = ssh_client.run("hostname -I | awk '{print $1}'")
            private_ip = private_ip_cmd.stdout.replace("\n", "")
            ip_address = ipaddress.ip_address(private_ip)
            if ip_address.is_global is True or ip_address.version == "6":
                private_ip_cmd = ssh_client.run("hostname -I | awk '{print $1}'")
                private_ip = private_ip_cmd.stdout.replace("\n", "")
                ip_address = ipaddress.ip_address(private_ip)
                if ip_address.is_global is True or ip_address.version == "6":
                    private_ip_cmd = ssh_client.run("hostname -I | awk '{print $2}'")
                    private_ip = private_ip_cmd.stdout.replace("\n", "")
                    ip_address = ipaddress.ip_address(private_ip)
                    if ip_address.is_global is True or ip_address.version == "6":
                        log.info("No private ip found")
                    else:
                        pri_address = private_ip
                else:
                    pri_address = private_ip
            else:
                pri_address = private_ip
        else:
            pri_address = private_ip
        return pri_address
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _get_ingress_public_ip(ssh_client: SSHClient, session_id: str, ip: str, username: str):
    try:
        public_ip = ssh_client.run(f"ssh -i {Config.PRAETOR_DIR}/id_rsa_{session_id} -o StrictHostKeyChecking=no "
                                   f"{username}@{ip} 'curl -s ifconfig.me'")
        return public_ip.stdout
    except Exception as e:
        raise e


def build_k8s_with_kubespray(ssh_client: SSHClient, session_id: str, provider_domain: str, attributes: list,
                             wallet_address: str, persistent_type: str, per_unit_prices: dict, chain_id: str):
    try:
        # start k8s process
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.START_K8S_PROCESS))

        gpu_process, gpu_type, gpu_model = get_gpu_data(session_id)

        if gpu_process is True:
            # Install NVIDIA Drivers and Toolkit
            _install_nvidia_drivers_and_toolkit(ssh_client, session_id)

        # install all kubespray requirements
        _install_kubespray_requirements(ssh_client, session_id)

        # generate host file for ansible playbook
        _generate_host_file(ssh_client, session_id)

        if gpu_process is True:
            _configure_nvidia_runtime(ssh_client, session_id)

        # Run ansible playbook
        _run_ansible_playbook(ssh_client, session_id)

        # copy the kubeconfig file and check the valid connection to the new kube
        _configure_kubectl(ssh_client, session_id)

        if gpu_process is True:
            time.sleep(3)
            update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.NVIDIA_HELM_INSTALL))
            install_nvidia_k8s_device_plugin(ssh_client, session_id)

        # make the newly created kubernetes ready for Akash Network
        _make_akash_ready(ssh_client, session_id, gpu_process, gpu_type, gpu_model, chain_id)

        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.PERSISTENT_STORAGE))
        enable_persistent_storage = get_persistent_storage_enable(session_id)
        if enable_persistent_storage is True:
            setup_persistent_storage(session_id, ssh_client)

        provider_services(ssh_client, session_id, provider_domain, attributes, wallet_address, persistent_type,
                          per_unit_prices, True)

        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.K8S_PROCESS_COMPLETED))
    except AuthenticationException as ae:
        update_k8s_process_step_error(session_id)
        raise ae
    except OSError as oe:
        update_k8s_process_step_error(session_id)
        raise oe
    except PraetorException as pe:
        update_k8s_process_step_error(session_id)
        raise pe
    except UnexpectedExit as ue:
        update_k8s_process_step_error(session_id)
        raise ue
    except Exception as e:
        update_k8s_process_step_error(session_id)
        raise e


def _install_nvidia_drivers_and_toolkit(ssh_client: SSHClient, session_id: str):
    try:
        key_file = f".praetor/id_rsa_{session_id}"
        time.sleep(5)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.NVIDIA_INSTALL))
        log.info(f"Prepare Environment for NVIDIA")

        ip_addresses = get_ip_addresses(session_id).split(" ")
        master_node = get_master_node(session_id)

        username = "root"
        if master_node is not None and ip_addresses is not None and len(ip_addresses) > 0:
            username = master_node["user_name"]

        for ip_address in ip_addresses:
            log.info(f"Installing nvidia packages for node({ip_address})...")
            # Call the function to check packages and get installation commands
            installation_packages = _check_nvidia_install_packages(ssh_client, session_id, ip_address, username)

            log.info(f"Installing packages, {installation_packages}")

            if len(installation_packages) > 0:
                # Perform system updates
                log.info("Performing system updates...")
                ssh_client.run(f"""ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "sudo DEBIAN_FRONTEND=noninteractive apt -qy -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dist-upgrade" """)
                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'sudo apt autoremove -y'")

                # reboot the server and sleep for 5 seconds
                try:
                    ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                                   f"'sudo reboot'")
                except UnexpectedExit:
                    log.info("Rebooting the server...")
                    time.sleep(5)

                # Check if the server is back online
                max_retries = 120
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        ssh_client.run(f"""ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "echo 'Server is online'" """)
                        log.info("Server is back online.")
                        break
                    except UnexpectedExit:
                        retry_count += 1
                        log.info(
                            f"Server is still offline. Retrying in 5 seconds... (Attempt {retry_count}/{max_retries})")
                        time.sleep(5)
                    except NoValidConnectionsError:
                        retry_count += 1
                        log.info(
                            f"Server is still offline. Retrying in 5 seconds... (Attempt {retry_count}/{max_retries})")
                        time.sleep(5)
                    except TimeoutError:
                        retry_count += 1
                        log.info(
                            f"Server is still offline. Retrying in 5 seconds... (Attempt {retry_count}/{max_retries})")
                        time.sleep(5)

                # Install Ubuntu drivers
                log.info("Installing Ubuntu drivers...")
                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'sudo apt install ubuntu-drivers-common -y'")
                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'sudo ubuntu-drivers devices'")
                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'sudo ubuntu-drivers autoinstall'")

                # Add NVIDIA container repository
                distribution_result = ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                                                     f"'. /etc/os-release;echo $ID$VERSION_ID'")
                distribution = distribution_result.stdout.replace("\n", "").replace("\r", "").lower()
                if distribution not in ["ubuntu18.04", "ubuntu20.04", "ubuntu22.04", "debian10", "debian11"]:
                    if distribution.startswith("ubuntu"):
                        distribution = "ubuntu22.04"
                    elif distribution.startswith("debian"):
                        distribution = "debian11"
                    else:
                        PraetorException("OS is not supported for nvidia drivers.")

                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'curl -s -L https://nvidia.github.io/libnvidia-container/gpgkey | sudo apt-key add -'")
                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'curl -s -L https://nvidia.github.io/libnvidia-container/{distribution}/libnvidia-container.list | sudo tee /etc/apt/sources.list.d/libnvidia-container.list'")

                # Install the missing packages
                installation_package = " ".join(installation_packages)
                log.info("Installing NVIDIA packages...")
                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'sudo apt-get update'")
                ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                               f"'sudo DEBIAN_FRONTEND=noninteractive apt-get install -qy {installation_package}'")

                # reboot the server and sleep for 5 seconds
                try:
                    ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                                   f"'sudo reboot'")
                except UnexpectedExit:
                    log.info("Rebooting the server...")
                    time.sleep(5)

                # Check if the server is back online
                max_retries = 120
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        ssh_client.run(f"""ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "echo 'Server is online'" """)
                        log.info("Server is back online.")
                        break
                    except UnexpectedExit:
                        retry_count += 1
                        log.info(
                            f"Server is still offline. Retrying in 5 seconds... (Attempt {retry_count}/{max_retries})")
                        time.sleep(5)
                    except NoValidConnectionsError:
                        retry_count += 1
                        log.info(
                            f"Server is still offline. Retrying in 5 seconds... (Attempt {retry_count}/{max_retries})")
                        time.sleep(5)
                    except TimeoutError:
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


def _check_nvidia_install_packages(ssh_client: SSHClient, session_id: str, ip_address: str, username: str):
    key_file = f".praetor/id_rsa_{session_id}"
    packages = ["nvidia-cuda-toolkit", "nvidia-container-toolkit"]

    installation_packages = []
    for package in packages:
        # Check if package is installed
        try:
            result = ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                                    f"'sudo dpkg -s {package}'")
            if "Status: install ok installed" not in result.stdout:
                # Package is not installed, add installation command
                installation_packages.append(f"{package}")
        except UnexpectedExit:
            # An error occurred while checking the package status, assume package is not installed
            installation_packages.append(f"{package}")

    # Check if nvidia-container-runtime file is present
    try:
        result = ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip_address} "
                                f"'sudo ls /usr/bin/nvidia-container-runtime'")
        if "No such file or directory" in result.stdout:
            # nvidia-container-runtime file is not present, add installation command
            installation_packages.append("nvidia-container-runtime")
    except UnexpectedExit:
        # An error occurred while checking the file, assume file is not present
        installation_packages.append("nvidia-container-runtime")

    return installation_packages


def _generate_host_file(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.PREPARE_ANSIBLE))

        log.info("Preparing machine for ansible build")
        username, ip_addresses = get_master_node_ip_addresses(session_id)

        ssh_client.run("cp -rfp kubespray/inventory/sample kubespray/inventory/akash")
        ssh_client.run(f"CONFIG_FILE=kubespray/inventory/akash/hosts.yaml KUBE_CONTROL_HOSTS=1 python3 "
                       f"kubespray/contrib/inventory_builder/inventory.py {ip_addresses}")
        ssh_client.run(f"""
ex kubespray/inventory/akash/hosts.yaml << eof
2 insert
  vars:
    cluster_id: "1.0.0.1"
    ansible_user: {username}
    gvisor_enabled: false
.
xit
eof
""")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _configure_nvidia_runtime(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.CONFIGURE_NVIDIA))

        log.info("Configuring NVIDIA Runtime")

        master_node = get_master_node(session_id)
        username = master_node["user_name"]

        ssh_client.run(f"""
cat > ~/kubespray/inventory/akash/group_vars/all/akash.yml <<'EOF'
ansible_user: {username}

ansible_connection: ssh

containerd_additional_runtimes:
  - name: nvidia
    type: "io.containerd.runc.v2"
    engine: ""
    root: ""
    options:
      BinaryName: "/usr/bin/nvidia-container-runtime"
EOF
""")
        log.info("NVIDIA runtime configured.")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_kubespray_requirements(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.KUBESPRAY_INSTALL))

        log.info("Installing kubespray requirements packages")
        pip_version = ssh_client.run("pip --version")
        python_version = pip_version.stdout.replace("\r", "").replace("\n", "").lower()

        version = python_version[python_version.find("(") + 1:python_version.find(")")].split(" ")[1]

        response_version = compare_versions(version, "3.10")

        if response_version is True:
            ssh_client.run("pip3 install --user --upgrade pip --break-system-packages")
            ssh_client.run("cd kubespray && pip3 install --user -r requirements.txt --break-system-packages")
        else:
            ssh_client.run("pip3 install --user --upgrade pip")
            ssh_client.run("cd kubespray && pip3 install --user -r requirements.txt")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _run_ansible_playbook(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.RUN_ANSIBLE))

        log.info("Running ansible playbook")
        present_working_directory_cmd = ssh_client.run(f"pwd")
        pwd = present_working_directory_cmd.stdout.replace("\n", "")

        ssh_client.run(f"export ANSIBLE_CONFIG=./kubespray/ansible.cfg && "
                       f"{pwd}/.local/bin/ansible-playbook -i kubespray/inventory/akash/hosts.yaml -b -v "
                       f"--private-key={Config.PRAETOR_DIR}/id_rsa_{session_id} kubespray/cluster.yml")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _configure_kubectl(ssh_client: SSHClient, session_id: str):
    try:
        time.sleep(5)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.KUBE_FILE_CONFIGURE))

        log.info("Configure kubernetes connection")
        # check if kube directory already exist, do not create
        ssh_client.run(f"[ -d {Config.KUBE_DIR} ] || mkdir {Config.KUBE_DIR}")

        # Copy Kubeconfig to the Provider
        master_node = get_master_node(session_id)
        if master_node is not None:
            ip = master_node["ip"]
            user = master_node["user_name"]
            ssh_client.run(f"ssh -i {Config.PRAETOR_DIR}/id_rsa_{session_id} "
                           f"{user}@{ip} 'sudo cat /etc/kubernetes/admin.conf' > ~/.kube/config")
            ssh_client.run(f"sed -i 's/127.0.0.1/{ip}/g' .kube/config")
        else:
            PraetorException("Master node does not exist for the session id", "P4046")

        # Install Kubectl on the Provider
        is_kubectl_exist = _kubectl_exist(ssh_client)
        if is_kubectl_exist is False:
            result = ssh_client.run("curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt")
            kube_ver = result.stdout

            google_url = f"https://storage.googleapis.com/kubernetes-release/release/{kube_ver}/bin/linux/amd64/kubectl"
            ssh_client.run(f"curl -LO {google_url}")

            ssh_client.run("chmod +x ./kubectl")
            ssh_client.run("mv ./kubectl /usr/local/bin/kubectl", True)

        # Verify Kubectl
        kube_connected = _check_kube_connection(ssh_client)
        if kube_connected is False:
            raise PraetorException("Kube files is not valid, Please upload valid file", "P5008")

    except AuthenticationException as ae:
        raise ae
    except OSError as oe:
        raise oe
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
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


def _make_akash_ready(ssh_client: SSHClient, session_id: str, gpu_process: bool, gpu_type: str,
                      gpu_model: str, chain_id: str):
    try:
        # Label node1 as an ingress role
        time.sleep(15)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.NODE_LABEL))
        log.info("Create label node1 as an ingress role")
        ssh_client.run(f"kubectl label --overwrite nodes node1 akash.network/role=ingress "
                       f"ingress-ready=true kubernetes.io/os=linux")

        # Create akash-service namespace
        time.sleep(3)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.NAMESPACE_CREATE))
        ssh_client.run(f"kubectl create ns akash-services")
        ssh_client.run(f"kubectl label ns akash-services akash.network/name=akash-services akash.network=true")

        ssh_client.run(f"kubectl create ns lease")
        ssh_client.run(f"kubectl label ns lease akash.network=true")

        # Apply akash hostname operator service
        time.sleep(3)
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.HOSTNAME_CREATE))
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
        update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.INGRESS_CREATE))
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
        if gpu_process is True:
            time.sleep(3)
            log.info("Labeling node1 with gpu vendor and gpu model")
            ssh_client.run(f"kubectl label --overwrite node node1 "
                           f"akash.network/capabilities.gpu.vendor.{gpu_type}.model.{gpu_model}=true "
                           f"allow-nvdp=true")

            log.info("Create runtime class for nvidia")
            update_k8s_process_step(session_id, calculate_k8s_process(K8sProcess.CREATE_NVIDIA_RUNTIME_CLASS))
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
