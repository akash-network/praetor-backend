def calculate_provider_resources_v31(manifest: dict, bidengine: dict, cluster: dict, cluster_public_hostname: str):
    try:
        deployments = manifest["deployments"] if manifest is not None and "deployments" in manifest else 0
        orders = bidengine["orders"] if bidengine is not None and "orders" in bidengine else 0
        leases = cluster["leases"] if cluster is not None and "leases" in cluster else 0
        cluster_public_hostname = cluster_public_hostname
        inventory = cluster["inventory"] if cluster is not None and "inventory" in cluster else None
        pending_obj = inventory["pending"] if inventory is not None and "pending" in inventory else None
        active_obj = inventory["active"] if inventory is not None and "active" in inventory else None
        available = inventory["available"] if inventory is not None and "available" in inventory else None
        available_nodes = available["nodes"] if available is not None and "nodes" in available else None
        available_storage = available["storage"] if available is not None and "storage" in available else None
        storage_class = available_storage[0]["class"] if available_storage is not None else None

        # Calculate total side of CPU, Memory, Storage Size of Available Provider
        available_cpu = 0
        available_gpu = 0
        available_memory = 0
        available_storage_ephemeral = 0
        available_storage_total = 0

        active_cpu = 0
        active_gpu = 0
        active_memory = 0
        active_storage_ephemeral = 0
        active_storage = 0
        allocatable_cpu, allocatable_gpu, allocatable_memory, allocatable_storage_ephemeral = 0, 0, 0, 0
        if available_nodes is not None:
            for node in available_nodes:
                available_node = node["available"]
                allocatable_node = node["allocatable"]

                available_cpu += available_node["cpu"]
                available_gpu += available_node["gpu"] if "gpu" in available_node else 0
                available_memory += available_node["memory"]
                available_storage_ephemeral += available_node["storage_ephemeral"]

                allocatable_cpu += allocatable_node["cpu"]
                allocatable_gpu += allocatable_node["gpu"] if "gpu" in allocatable_node else 0
                allocatable_memory += allocatable_node["memory"]
                allocatable_storage_ephemeral += allocatable_node["storage_ephemeral"]

                active_cpu = allocatable_cpu - available_cpu
                active_gpu = allocatable_gpu - available_gpu
                active_memory = allocatable_memory - available_memory
                active_storage_ephemeral = allocatable_storage_ephemeral - available_storage_ephemeral

        if available_storage is not None:
            for available_storage_class in available_storage:
                available_storage_total += available_storage_class["size"]

        # Calculate total side of CPU, Memory, Storage Size of Pending Provider
        pending_cpu = 0
        pending_gpu = 0
        pending_memory = 0
        pending_storage_ephemeral = 0
        pending_storage = 0
        if pending_obj is not None:
            for pending_rec in pending_obj:
                pending_cpu += pending_rec["cpu"]
                pending_gpu += pending_rec["gpu"] if "gpu" in pending_rec else 0
                pending_memory += pending_rec["memory"]
                pending_storage_ephemeral += pending_rec["storage_ephemeral"]
                pending_storage += pending_rec["storage"][storage_class] \
                    if "storage" in pending_rec and storage_class in pending_rec["storage"] else 0

        # Create Provider Object
        provider_obj = {
            "deployments": deployments,
            "orders": orders,
            "leases": leases,
            "storage_class": storage_class,
            "active_resources": {
                "cpu": (active_cpu / 1000) if active_cpu > 0 else 0,
                "gpu": active_gpu,
                "memory": active_memory,
                "storage_ephemeral": active_storage_ephemeral,
                "storage": active_storage
            },
            "available_resources": {
                "cpu": (available_cpu / 1000) if available_cpu > 0 else 0,
                "gpu": available_gpu,
                "memory": available_memory,
                "storage_ephemeral": available_storage_ephemeral,
                "storage": available_storage_total
            },
            "pending_resources": {
                "cpu": (pending_cpu / 1000) if pending_cpu > 0 else 0,
                "gpu": pending_gpu,
                "memory": pending_memory,
                "storage_ephemeral": pending_storage_ephemeral,
                "storage": pending_storage
            },
            "cluster_public_hostname": cluster_public_hostname,
        }
        return provider_obj
    except (KeyError, TypeError):
        return calculate_provider_resources_v23(manifest, bidengine, cluster, cluster_public_hostname)
    except Exception as e:
        raise e


def calculate_provider_resources_v23(manifest: dict, bidengine: dict, cluster: dict, cluster_public_hostname: str):
    try:
        deployments = manifest["deployments"] if manifest is not None and "deployments" in manifest else 0
        orders = bidengine["orders"] if bidengine is not None and "orders" in bidengine else 0
        leases = cluster["leases"] if cluster is not None and "leases" in cluster else 0
        cluster_public_hostname = cluster_public_hostname
        inventory = cluster["inventory"] if cluster is not None and "inventory" in cluster else None
        pending_obj = inventory["pending"] if inventory is not None and "pending" in inventory else None
        active_obj = inventory["active"] if inventory is not None and "active" in inventory else None
        available = inventory["available"] if inventory is not None and "available" in inventory else None
        available_nodes = available["nodes"] if available is not None and "nodes" in available else None
        available_storage = available["storage"] if available is not None and "storage" in available else None
        storage_class = available_storage[0]["class"] if available_storage is not None else None

        # Calculate total side of CPU, Memory, Storage Size of Available Provider
        available_cpu = 0
        available_gpu = 0
        available_memory = 0
        available_storage_ephemeral = 0
        available_storage_total = 0
        if available_nodes is not None:
            for available_node in available_nodes:
                available_cpu += available_node["cpu"]
                available_gpu += available_node["gpu"] if "gpu" in available_node else 0
                available_memory += available_node["memory"]
                available_storage_ephemeral += available_node["storage_ephemeral"]

        if available_storage is not None:
            for available_storage_class in available_storage:
                available_storage_total += available_storage_class["size"]

        # Calculate total side of CPU, Memory, Storage Size of Active Provider
        active_cpu = 0
        active_gpu = 0
        active_memory = 0
        active_storage_ephemeral = 0
        active_storage = 0
        if active_obj is not None:
            for active_rec in active_obj:
                active_cpu += active_rec["cpu"]
                active_gpu += active_rec["gpu"] if "gpu" in active_rec else 0
                active_memory += active_rec["memory"]
                active_storage_ephemeral += active_rec["storage_ephemeral"]
                active_storage += active_rec["storage"][storage_class] \
                    if "storage" in active_rec and storage_class in active_rec["storage"] else 0

        # Calculate total side of CPU, Memory, Storage Size of Pending Provider
        pending_cpu = 0
        pending_gpu = 0
        pending_memory = 0
        pending_storage_ephemeral = 0
        pending_storage = 0
        if pending_obj is not None:
            for pending_rec in pending_obj:
                pending_cpu += pending_rec["cpu"]
                pending_gpu += pending_rec["gpu"] if "gpu" in pending_rec else 0
                pending_memory += pending_rec["memory"]
                pending_storage_ephemeral += pending_rec["storage_ephemeral"]
                pending_storage += pending_rec["storage"][storage_class] \
                    if "storage" in pending_rec and storage_class in pending_rec["storage"] else 0

        # Create Provider Object
        provider_obj = {
            "deployments": deployments,
            "orders": orders,
            "leases": leases,
            "storage_class": storage_class,
            "active_resources": {
                "cpu": (active_cpu / 1000) if active_cpu > 0 else 0,
                "gpu": active_gpu,
                "memory": active_memory,
                "storage_ephemeral": active_storage_ephemeral,
                "storage": active_storage
            },
            "available_resources": {
                "cpu": (available_cpu / 1000) if available_cpu > 0 else 0,
                "gpu": available_gpu,
                "memory": available_memory,
                "storage_ephemeral": available_storage_ephemeral,
                "storage": available_storage_total
            },
            "pending_resources": {
                "cpu": (pending_cpu / 1000) if pending_cpu > 0 else 0,
                "gpu": pending_gpu,
                "memory": pending_memory,
                "storage_ephemeral": pending_storage_ephemeral,
                "storage": pending_storage
            },
            "cluster_public_hostname": cluster_public_hostname,
        }
        return provider_obj
    except (KeyError, TypeError):
        return calculate_provider_resources_v16(manifest, bidengine, cluster, cluster_public_hostname)
    except Exception as e:
        raise e


def calculate_provider_resources_v16(manifest: dict, bidengine: dict, cluster: dict, cluster_public_hostname: str):
    try:
        deployments = manifest["deployments"] if manifest is not None and "deployments" in manifest else 0
        orders = bidengine["orders"] if bidengine is not None and "orders" in bidengine else 0
        leases = cluster["leases"] if cluster is not None and "leases" in cluster else 0
        cluster_public_hostname = cluster_public_hostname
        inventory = cluster["inventory"] if cluster is not None and "inventory" in cluster else None
        pending_obj = inventory["pending"] if inventory is not None and "pending" in inventory else None
        active_obj = inventory["active"] if inventory is not None and "active" in inventory else None
        available = inventory["available"] if inventory is not None and "available" in inventory else None
        available_nodes = available["nodes"] if available is not None and "nodes" in available else None
        available_storage = available["storage"] if available is not None and "storage" in available else None
        storage_class = available_storage[0]["class"] if available_storage is not None else None

        # Calculate total side of CPU, Memory, Storage Size of Available Provider
        available_cpu = 0
        available_memory = 0
        available_storage_ephemeral = 0
        available_storage_total = 0
        if available_nodes is not None:
            for available_node in available_nodes:
                available_cpu += available_node["cpu"]
                available_memory += available_node["memory"]
                available_storage_ephemeral += available_node["storage_ephemeral"]

        if available_storage is not None:
            for available_storage_class in available_storage:
                available_storage_total += available_storage_class["size"]

        # Calculate total side of CPU, Memory, Storage Size of Active Provider
        active_cpu = 0
        active_memory = 0
        active_storage_ephemeral = 0
        active_storage = 0
        if active_obj is not None:
            for active_rec in active_obj:
                active_cpu += active_rec["cpu"]
                active_memory += active_rec["memory"]
                active_storage_ephemeral += active_rec["storage_ephemeral"]
                active_storage += active_rec["storage"][storage_class] if "storage" in active_rec else 0

        # Calculate total side of CPU, Memory, Storage Size of Pending Provider
        pending_cpu = 0
        pending_memory = 0
        pending_storage_ephemeral = 0
        pending_storage = 0
        if pending_obj is not None:
            for pending_rec in pending_obj:
                pending_cpu += pending_rec["cpu"]
                pending_memory += pending_rec["memory"]
                pending_storage_ephemeral += pending_rec["storage_ephemeral"]
                pending_storage += pending_rec["storage"][storage_class] if "storage" in pending_rec else 0

        # Create Provider Object
        provider_obj = {
            "deployments": deployments,
            "orders": orders,
            "leases": leases,
            "storage_class": storage_class,
            "active_resources": {
                "cpu": (active_cpu / 1000) if active_cpu > 0 else 0,
                "memory": active_memory,
                "storage_ephemeral": active_storage_ephemeral,
                "storage": active_storage
            },
            "available_resources": {
                "cpu": (available_cpu / 1000) if available_cpu > 0 else 0,
                "memory": available_memory,
                "storage_ephemeral": available_storage_ephemeral,
                "storage": available_storage_total
            },
            "pending_resources": {
                "cpu": (pending_cpu / 1000) if pending_cpu > 0 else 0,
                "memory": pending_memory,
                "storage_ephemeral": pending_storage_ephemeral,
                "storage": pending_storage
            },
            "cluster_public_hostname": cluster_public_hostname,
        }
        return provider_obj
    except (KeyError, TypeError):
        return calculate_provider_resources_v14(manifest, bidengine, cluster, cluster_public_hostname)
    except Exception as e:
        raise e


def calculate_provider_resources_v14(manifest: dict, bidengine: dict, cluster: dict, cluster_public_hostname: str):
    try:
        deployments = manifest["deployments"] if manifest is not None and "deployments" in manifest else 0
        orders = bidengine["orders"] if bidengine is not None and "orders" in bidengine else 0
        leases = cluster["leases"] if cluster is not None and "leases" in cluster else 0
        cluster_public_hostname = cluster_public_hostname
        pending_obj = cluster["inventory"]["pending"]
        active_obj = cluster["inventory"]["active"]
        available_obj = cluster["inventory"]["available"]

        # Calculate total side of CPU, Memory, Storage Size of Available Provider
        available_cpu = 0
        available_memory = 0
        available_storage_ephemeral = 0
        if available_obj is not None:
            for available_rec in available_obj:
                available_cpu += int(available_rec["cpu"]["units"]["val"])
                available_memory += int(available_rec["memory"]["size"]["val"])
                available_storage_ephemeral += int(available_rec["storage"]["size"]["val"])

        # Calculate total side of CPU, Memory, Storage Size of Active Provider
        active_cpu = 0
        active_memory = 0
        active_storage_ephemeral = 0
        if active_obj is not None:
            for active_rec in active_obj:
                active_cpu += int(active_rec["cpu"]["units"]["val"])
                active_memory += int(active_rec["memory"]["size"]["val"])
                active_storage_ephemeral += int(active_rec["storage"]["size"]["val"])

        # Calculate total side of CPU, Memory, Storage Size of Pending Provider
        pending_cpu = 0
        pending_memory = 0
        pending_storage_ephemeral = 0
        if pending_obj is not None:
            for pending_rec in pending_obj:
                pending_cpu += int(pending_rec["cpu"]["units"]["val"])
                pending_memory += int(pending_rec["memory"]["size"]["val"])
                pending_storage_ephemeral += int(pending_rec["storage"]["size"]["val"])

        # Create Provider Object
        provider_obj = {
            "deployments": deployments,
            "orders": orders,
            "leases": leases,
            "active_resources": {
                "cpu": (active_cpu / 1000) if active_cpu > 0 else 0,
                "memory": active_memory,
                "storage_ephemeral": active_storage_ephemeral
            },
            "available_resources": {
                "cpu": (available_cpu / 1000) if available_cpu > 0 else 0,
                "memory": available_memory,
                "storage_ephemeral": available_storage_ephemeral
            },
            "pending_resources": {
                "cpu": (pending_cpu / 1000) if pending_cpu > 0 else 0,
                "memory": pending_memory,
                "storage_ephemeral": pending_storage_ephemeral
            },
            "cluster_public_hostname": cluster_public_hostname,
        }
        return provider_obj
    except TypeError as te:
        raise te
    except Exception as e:
        raise e
