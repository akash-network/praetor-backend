from datetime import datetime, timedelta


from application.config.mongodb import sessions_collection
from application.model.stage import Stage


def update_session(search_query: dict, update: dict, upsert: bool = False):
    return sessions_collection.update_one(search_query, update, upsert=upsert)


def get_session(search_query: dict, fields: list = None, get_internal_id: bool = False):
    select_fields = {field: 1 for field in fields} if fields is not None else None
    select_fields["_id"] = get_internal_id
    return sessions_collection.find_one(search_query, select_fields, sort=[("created", -1)])


def get_session_id_for_completed_session(wallet_address: str):
    session = get_session({"wallet_address": wallet_address,
                           "stage": {"$in": ["K8S_PROCESS_COMPLETED", "PROVIDER_PROCESS_COMPLETED"]}}, ["stage"], True)
    if session is not None and "stage" in session:
        if session["stage"] in ["K8S_PROCESS_COMPLETED", "PROVIDER_PROCESS_COMPLETED"]:
            return session["_id"]
        else:
            return None
    else:
        return None


def get_stage_from_session_id(session_id: str):
    # Return Stage from database based on session id
    return get_session({"_id": session_id}, ["stage"])


def get_log_from_session_id(session_id: str):
    # Return logs from database based on session id
    return get_session({"_id": session_id}, ["logs"])


def get_os_from_session_id(session_id: str):
    # Return Operating System from database based on session id
    return get_session({"_id": session_id}, ["os"])


def update_session_stage(session_id: str, stage: Stage):
    # Update Stage in database based on session id
    current_date = datetime.utcnow()
    if stage == stage.NODE_VERIFIED:
        update_session({"_id": session_id}, {"$set": {"stage": stage.name, "modified": current_date}})
    else:
        update_session({"_id": session_id}, {"$set": {"stage": stage.name, "modified": current_date}})


def update_session_logs(session_id: str, logs: str):
    # Update logs in database based on session id
    exist_logs = _get_log_from_session_id(session_id)
    if not exist_logs:
        updated_logs = logs
    else:
        exist_logs = exist_logs["logs"]
        updated_logs = f"{exist_logs} ,{logs}"
    update_session({"_id": session_id}, {"$set": {"logs": updated_logs}})


def update_session_os(session_id: str, operating_system: str):
    # Update Operating System in database based on session id
    current_date = datetime.utcnow()

    update_session({"_id": session_id}, {"$set": {"os": operating_system, "created": current_date}}, True)


def update_wallet_address(session_id: str, wallet_address: str):
    # Update Wallet Address in database based on session id
    update_session({"_id": session_id}, {"$set": {"wallet_address": wallet_address}})


def update_chain_id(session_id: str, chain_id: str):
    # Update chainid in database based on session id
    update_session({"_id": session_id}, {"$set": {"chainid": chain_id}})


def get_chain_id(session_id: str):
    # Return chainid from database based on session id
    session = get_session({"_id": session_id}, ["chainid"])
    if "chainid" in session:
        return session["chainid"]
    else:
        return None


def update_provider_service_type(session_id: str, provider_service_type: str):
    # Update provider service type in database based on session id
    update_session({"_id": session_id}, {"$set": {"provider_service_type": provider_service_type}})


def get_provider_service_type(session_id: str):
    # Return provider service type from database based on session id
    session = get_session({"_id": session_id}, ["provider_service_type"])
    if "provider_service_type" in session:
        return session["provider_service_type"]
    else:
        return None


def update_kube_build(session_id: str, kube_build_obj: dict):
    # Update kube build object for session id
    update_session({"_id": session_id}, {"$set": {"kube_build": kube_build_obj}})


def get_kube_build(session_id: str):
    session = get_session({"_id": session_id}, ["kube_build"])
    if "kube_build" in session:
        return session["kube_build"]
    else:
        return None


def update_gpu_config(session_id: str, gpu_config_obj: dict):
    # Update GPU config object for session id
    update_session({"_id": session_id}, {"$set": {"gpu_config": gpu_config_obj}})


def get_gpu_config(session_id: str):
    session = get_session({"_id": session_id}, ["gpu_config"])
    if "gpu_config" in session:
        return session["gpu_config"]
    else:
        return None


def update_provider_request(session_id: str, provider_request: dict):
    # Update provider request object for session id
    update_session({"_id": session_id}, {"$set": {"provider_request": provider_request}})


def get_provider_request(session_id: str):
    session = get_session({"_id": session_id}, ["provider_request"])
    if "provider_request" in session:
        return session["provider_request"]
    else:
        return None


def update_k3s_process_step(session_id: str, k3s_process_step: dict):
    step_name = k3s_process_step["step_name"]
    update_session_stage(session_id, Stage[step_name])
    update_session({"_id": session_id}, {"$set": {"k3s_process": k3s_process_step}})


def update_k8s_process_step(session_id: str, k8s_process_step: dict):
    step_name = k8s_process_step["step_name"]
    update_session_stage(session_id, Stage[step_name])
    update_session({"_id": session_id}, {"$set": {"k8s_process": k8s_process_step}})


def update_k8s_process_step_error(session_id: str):
    step_name = Stage.K8S_ERROR.name
    update_session_stage(session_id, Stage[step_name])
    update_session({"_id": session_id}, {"$set": {"k8s_process.step_name": step_name, "k8s_process.percentage": -1}})


def update_provider_process_step(session_id: str, provider_process_step: dict):
    step_name = provider_process_step["step_name"]
    update_session_stage(session_id, Stage[step_name])
    update_session({"_id": session_id}, {"$set": {"provider_process": provider_process_step}})


def update_ip_addresses(session_id: str, ip_addresses: str):
    update_session({"_id": session_id}, {"$set": {"ip_addresses": ip_addresses}})


def get_ip_addresses(session_id: str):
    session = get_session({"_id": session_id}, ["ip_addresses"])
    if "ip_addresses" in session:
        return session["ip_addresses"]
    else:
        return None


def update_nodes(session_id: str, nodes: list):
    update_session({"_id": session_id}, {"$set": {"nodes": nodes}})


def get_nodes(session_id: str):
    session = get_session({"_id": session_id}, ["nodes"])
    if "nodes" in session:
        return session["nodes"]
    else:
        return None


def update_persistent_storage(session_id: str, persistent_storage: dict):
    update_session({"_id": session_id}, {"$set": persistent_storage})


def get_persistent_storage_enable(session_id: str):
    session = get_session({"_id": session_id}, ["persistent_storage_enable"])
    if "persistent_storage_enable" in session:
        return session["persistent_storage_enable"]
    else:
        return None


def get_persistent_storage(session_id: str):
    session = get_session({"_id": session_id}, ["persistent_storage"])
    if "persistent_storage" in session:
        return session["persistent_storage"]
    else:
        return None


def update_master_node(session_id: str, master_node_detail: dict):
    update_session({"_id": session_id}, {"$set": {"master_node": master_node_detail}})


def get_master_node(session_id: str):
    session = get_session({"_id": session_id}, ["master_node"])
    if "master_node" in session:
        return session["master_node"]
    else:
        return None


def get_master_node_ip_addresses(session_id: str):
    session = get_session({"_id": session_id}, ["master_node", "ip_addresses"])
    if "master_node" in session and "ip_addresses" in session:
        return session["master_node"]["user_name"], session["ip_addresses"]
    else:
        return None, None


def _get_log_from_session_id(session_id: str):
    # Return logs from database based on session id
    return get_session({"_id": session_id}, ["logs"])


def get_stage_and_process_step(session_id: str, process_name: str):
    return get_session({"_id": session_id}, ["stage", process_name])


def get_active_process_status(address: str):
    session = get_session({"wallet_address": address}, ["k8s_process", "provider_request"])
    if session is not None and "k8s_process" in session and "provider_request" in session:
        k8s_process = session["k8s_process"]
        provider_request = session["provider_request"]
        return k8s_process, provider_request


def get_k8s_process_status_by_address(address: str):
    session = get_session({"wallet_address": address}, ["k8s_process"])
    if session is not None and "k8s_process" in session:
        k8s_process = session["k8s_process"]
        percentage = k8s_process["percentage"]
        if 0 <= percentage < 100:
            return True
        else:
            return False
    else:
        return False


def update_installation_error(session_id: str, installation_status: dict):
    # Update Akash & Dependecies error flag in database based on session id
    update_session({"_id": session_id}, {"$set": {"installation_status": installation_status}})


def get_installation_status(session_id: str):
    session = get_session({"_id": session_id}, ["installation_status"])
    if "installation_status" in session:
        return session["installation_status"]
    else:
        return None


def get_successful_praetor_providers():
    wallet_addresses = []
    sessions = sessions_collection.aggregate(
        [{"$match": {"wallet_address": {"$ne": None}, "stage": "PROVIDER_PROCESS_COMPLETED"}},
         {"$group": {"_id": "$wallet_address", "wallet_address": {"$first": "$wallet_address"}}}])
    for session in sessions:
        wallet_addresses.append(session["wallet_address"])
    return wallet_addresses


def get_stage_and_provider_request(address: str):
    session = get_session({"wallet_address": address}, ["stage", "provider_request", "kube_build", "os",
                                                        "chainid", "provider_service_type"])
    if session is not None and "stage" in session and "provider_request" in session:
        provider_request = session["provider_request"]
        last_stage = session["stage"]
        kube_build = session["kube_build"]
        os = session["os"]
        chainid = session["chainid"]
        provider_service_type = session["provider_service_type"]
        return provider_request, last_stage, kube_build, os, chainid, provider_service_type


def insert_new_session_data(session_id: str, wallet_address: str):
    # get last stage and other provider details from database from wallet address
    provider_request, last_stage, kube_build, os, chainid, provider_service_type = get_stage_and_provider_request(wallet_address)

    current_date = datetime.utcnow()
    insert_obj = {
        "wallet_address": wallet_address,
        "os": os,
        "stage": last_stage,
        "provider_request": provider_request,
        "kube_build": kube_build,
        "created": current_date,
        "chainid": chainid,
        "provider_service_type": provider_service_type
    }
    update_session({"_id": session_id}, {"$set": insert_obj}, True)


def update_bid_price_session_data(bid_request):
    try:
        current_date = datetime.utcnow()
        update_obj = {
            "provider_request.bid_price_cpu_scale": bid_request.bid_price_cpu_scale,
            "provider_request.bid_price_memory_scale": bid_request.bid_price_memory_scale,
            "provider_request.bid_price_storage_scale": bid_request.bid_price_storage_scale,
            "provider_request.bid_price_pres_hdd_scale": bid_request.bid_price_hd_pres_hdd_scale,
            "provider_request.bid_price_pres_ssd_scale": bid_request.bid_price_hd_pres_ssd_scale,
            "provider_request.bid_price_pres_nvme_scale": bid_request.bid_price_hd_pres_nvme_scale,
            "provider_request.bid_price_endpoint_scale": bid_request.bid_price_endpoint_scale,
            "provider_request.bid_price_ip_scale": bid_request.bid_price_ip_scale,
            "provider_request.bid_price_gpu_scale": bid_request.bid_price_gpu_scale,
            "modified": current_date
        }
        update_session({"_id": bid_request.session_id}, {"$set": update_obj})
    except Exception as e:
        raise e


def update_provider_url(session_id: str, provider_domain: str):
    try:
        current_date = datetime.utcnow()
        url_obj = {
            "provider_request.domain_name": provider_domain,
            "modified": current_date
        }
        update_session({"_id": session_id}, {"$set": url_obj})
    except Exception as e:
        raise e


def get_wallet_address(session_id: str):
    session = get_session({"_id": session_id}, ["wallet_address"])
    if "wallet_address" in session:
        return session["wallet_address"]
    else:
        return None


def update_provider_attributes(session_id: str, provider_attributes: list):
    try:
        current_date = datetime.utcnow()
        attribute_obj = {
            "provider_request.attributes": provider_attributes,
            "modified": current_date
        }
        update_session({"_id": session_id}, {"$set": attribute_obj})
    except Exception as e:
        raise e


def get_providers_session():
    try:
        yesterday = datetime.now() - timedelta(days=1)
        sessions = list(sessions_collection.find({"modified": {"$gte": yesterday}}))
        return sessions
    except Exception as e:
        raise e
