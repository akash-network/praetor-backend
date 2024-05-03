import json
import time

from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException

from application.config.config import Config
from application.data.session import get_nodes, update_persistent_storage, get_persistent_storage
from application.utils.cache import load_object
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def get_persistent_drives(session_id: str):
    key_file = f".praetor/id_rsa_{session_id}"

    try:
        ssh_client = load_object(session_id)
        nodes = get_nodes(session_id)
        drives = []

        for x, node in enumerate(nodes):
            if x == 0:
                continue

            ip, username = node["ip"], node["username"]

            lsblk_command = ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip} "
                                           f"'lsblk -o name,size,rota -J'")
            lsblk_json = json.loads(lsblk_command.stdout)
            block_devices = lsblk_json["blockdevices"]

            for block_device in block_devices:
                block_device_children = block_device["children"] if "children" in block_device else None
                if block_device_children is None:
                    storage_type = "hdd"
                    storage_type = "nvme" if "nvme" in block_device["name"] else storage_type
                    storage_type = "ssd" if storage_type != "nvme" and block_device["rota"] is False else storage_type

                    drives.append({"drive_name": block_device["name"], "node_name": f"node{x+1}", "ip": ip,
                                   "size": block_device["size"], "storage_type": storage_type, "username": username})

        update_persistent_storage(session_id, {"persistent_storage_enable": False})
        return drives
    except Exception as e:
        raise e


def update_persistent_drives(session_id: str, drives: list):
    try:
        drive_names, node_names, storage_nodes, storage_type = [], [], [], ""

        storage_class_and_osds = {
            "hdd": {"class": "beta1", "number_of_osds": 2},
            "ssd": {"class": "beta2", "number_of_osds": 3},
            "nvme": {"class": "beta3", "number_of_osds": 5}
        }

        for drive in drives:
            drive_name_regex = f"""^{drive["drive_name"][0:2]}."""
            if drive_name_regex not in drive_names:
                drive_names.append(drive_name_regex)
            if drive["node_name"] not in node_names:
                storage_nodes.append({"ip": drive["ip"], "username": drive["username"]})
                node_names.append(drive["node_name"])
            storage_type = drive["storage_type"]

        current_class_and_osds = storage_class_and_osds[storage_type]
        persistent_storage_enable = True if len(drives) > 0 else False
        if persistent_storage_enable is True:
            persistent_storage = {"persistent_storage_enable": persistent_storage_enable,
                                  "persistent_storage": {"drive_names": drive_names, "node_names": node_names,
                                                         "storage_type": storage_type, "storage_nodes": storage_nodes,
                                                         "storage_class": current_class_and_osds["class"],
                                                         "number_of_osds": current_class_and_osds["number_of_osds"]}}
            update_persistent_storage(session_id, persistent_storage)
        return {"storage_type": storage_type, "storage_class": current_class_and_osds["class"]}
    except Exception as e:
        raise e


def setup_persistent_storage(session_id: str, ssh_client: SSHClient):
    try:
        persistent_storage = get_persistent_storage(session_id)

        storage_nodes = persistent_storage["storage_nodes"]
        drive_names = persistent_storage["drive_names"]
        node_names = persistent_storage["node_names"]
        persistent_storage_class = persistent_storage["storage_class"]
        number_of_osds = persistent_storage["number_of_osds"]

        _make_instances_ready(ssh_client, session_id, storage_nodes)
        _add_akash_repo(ssh_client)
        _install_rook_crd(ssh_client)
        _create_rook_yaml(ssh_client, persistent_storage_class, drive_names, number_of_osds, node_names)
        _install_helm_chart_rook(ssh_client)
        _check_persistent_storage_status(ssh_client)
        _label_nodes_for_persistent_storage(ssh_client, node_names, persistent_storage_class)
        _install_akash_inventory_operator(ssh_client)

        return persistent_storage_class
    except Exception as e:
        raise e


def _make_instances_ready(ssh_client: SSHClient, session_id: str, storage_nodes: list):
    try:
        key_file = f".praetor/id_rsa_{session_id}"

        for storage_node in storage_nodes:
            ip = storage_node["ip"]
            username = storage_node["username"]

            log.info(f"Installing lvm2 package for {ip}")

            ssh_client.run(f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{ip} "
                           f"'sudo apt-get install -y lvm2'")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _add_akash_repo(ssh_client: SSHClient):
    try:
        log.info("Adding akash repo to helm chart")
        ssh_client.run("helm repo add akash https://akash-network.github.io/helm-charts")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_rook_crd(ssh_client: SSHClient):
    try:
        log.info("Installing akash rook CRDs")
        helm_chart_url = "https://raw.githubusercontent.com/akash-network/helm-charts"
        ssh_client.run(f"kubectl apply -f {helm_chart_url}/provider-0.172.0/charts/akash-rook/crds.yaml")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _create_rook_yaml(ssh_client: SSHClient, persistent_storage_class: str, drive_names: list,
                      osds_per_device: int, node_names: list):
    try:
        log.info("Creating rook yaml file")
        ssh_client.run(f"""
cat <<EOF | tee {Config.PRAETOR_DIR}/rook.yaml
persistent_storage:
  class: {persistent_storage_class}

useAllDevices: false
deviceFilter: {",".join(drive_names)}

mgrCount: 2
monCount: 3
osdsPerDevice: {osds_per_device}
nodes:
EOF
""")

        for node_name in node_names:
            ssh_client.run(f"""
cat <<EOF | tee -a {Config.PRAETOR_DIR}/rook.yaml
    - name: {node_name}
      config: ""
EOF
""")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_helm_chart_rook(ssh_client: SSHClient):
    try:
        log.info("Installing provider helm chart for akash rook")
        ssh_client.run(f"helm install akash-rook akash/akash-rook -n akash-services -f {Config.PRAETOR_DIR}/rook.yaml")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _check_persistent_storage_status(ssh_client: SSHClient):
    try:
        try_count = 0
        health_ok = False
        while try_count <= 15 and health_ok is False:
            try_count += 1
            log.info(f"Trying to check the ceph cluster status... try count {try_count}.")

            time.sleep(30)

            ceph_cluster_result = ssh_client.run("kubectl -n rook-ceph get cephclusters -o json")
            ceph_cluster = json.loads(ceph_cluster_result.stdout)
            ceph_cluster_status = ceph_cluster["items"][0]["status"] if "status" in ceph_cluster["items"][0] else None
            health = ceph_cluster_status["ceph"]["health"] if \
                (ceph_cluster_status is not None and "ceph" in ceph_cluster_status) else None

            if health is not None and health == "HEALTH_OK":
                log.info(f"Ceph rook health check is okay.")
                health_ok = True
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _label_nodes_for_persistent_storage(ssh_client: SSHClient, node_names: list, storage_class: str):
    try:
        for node_name in node_names:
            log.info(f"Labeling {node_name} for storage class")
            ssh_client.run(f"kubectl label node {node_name} akash.network/storageclasses={storage_class} --overwrite")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _install_akash_inventory_operator(ssh_client: SSHClient):
    try:
        log.info("Installing inventory operator")
        ssh_client.run(f"helm install inventory-operator akash/akash-inventory-operator -n akash-services")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e
