import time
from pymongo import UpdateOne, UpdateMany
import socket
from paramiko.ssh_exception import AuthenticationException

from application.config.config import Config
from application.data.session import get_successful_praetor_providers
from application.config.mongodb import providers_collection
from application.exception.praetor_exception import PraetorException
from application.service.calculate_resources import calculate_provider_resources_v31
from application.service.common import check_on_chain_provider_service_status
from application.service.ip_api import get_provider_locations
from application.utils.logger import log


def upsert_many_provider(providers, chain_id: str):
    host_uris = []
    duplicate_host_uris = []
    providers_list = []
    for provider in providers:
        if provider["host_uri"] not in host_uris:
            host_uris.append(provider["host_uri"])
        else:
            duplicate_host_uris.append((provider["host_uri"]))

    upserts = []
    for provider in providers:
        current_time = int(time.time())
        owner = provider["owner"]
        del provider["owner"]
        upserts.append(UpdateOne({"owner": owner, "chainid": chain_id},
                                 {"$setOnInsert": {"owner": owner, "chainid": chain_id, "created": current_time},
                                  "$set": provider}, upsert=True))
    providers_collection.bulk_write(upserts)

    for host_uri in host_uris:
        duplicate = False
        if host_uri in duplicate_host_uris:
            duplicate = True
        providers_collection.update_many({"host_uri": host_uri}, {"$set": {"duplicate_uri": duplicate}})

    for provider in providers_collection.find({"chainid": chain_id}, {"_id": 0}):
        providers_list.append(provider)

    return providers_list


def update_many_provider(ssh_client, providers, chain_id):
    try:
        provider_ip_list = []
        update_cluster_operations = []
        update_online_history_operations = []
        update_provider_location_operations = []
        praetor_provider_addresses = get_successful_praetor_providers()
        for provider in providers:
            if provider["owner"] in praetor_provider_addresses:
                provider["praetor"] = True
            else:
                provider["praetor"] = False

            if provider["connected"] is True and provider["duplicate_uri"] is True:
                provider_online_status = check_on_chain_provider_service_status(ssh_client, provider["owner"],
                                                                                chain_id, True)
                provider["connected"] = False if provider_online_status is False else True

            if provider["connected"] is True:
                try:
                    provider["ip_address"] = socket.gethostbyname(provider["provider_url"])
                    provider_ip_list.append(provider["ip_address"])
                    # provider["location"] = get_provider_location_by_ip(provider["ip_address"])
                except socket.gaierror:
                    log.info(f"Provider url is wrong - {provider['cluster_public_hostname']}")

            if (("cluster_public_hostname" in provider and
                 provider["cluster_public_hostname"] in Config.EXCLUDED_HOSTNAMES.split(",")) or
                    (provider["owner"] in Config.EXCLUDED_OWNERS.split(","))):
                continue
            else:
                update_cluster_operations.append(UpdateOne({"owner": provider["owner"], "chainid": chain_id},
                                                           {"$set": provider}))
                online_history = {
                    "online_history": {
                        "$each": [provider["connected"]],
                        "$slice": -2000 if chain_id == Config.CHAIN_ID else -6000
                    }
                }
                update_online_history_operations.append(UpdateOne({"owner": provider["owner"], "chainid": chain_id},
                                                                  {"$push": online_history}))

        provider_locations = get_provider_locations(provider_ip_list)
        for provider_location in provider_locations:
            update_provider_location_operations.append(UpdateMany({"ip_address": provider_location["query"]},
                                                                  {"$set": {"provider_location": provider_location}}))

        providers_collection.bulk_write(update_cluster_operations)
        providers_collection.bulk_write(update_online_history_operations)
        providers_collection.bulk_write(update_provider_location_operations)
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except Exception as e:
        raise e


def update_provider(search_query, update, upsert=False):
    return providers_collection.update_one(search_query, update, upsert=upsert)


def get_all_providers(chain_id: str):
    active_providers, inactive_providers, unique_host_uris, note = [], [], [], ""

    # Get current utc date
    current_time = int(time.time())

    active_providers_cursor = providers_collection.find({"connected": True, "chainid": chain_id}, {"_id": 0},
                                                        sort=[("praetor", -1)])
    for active_provider in active_providers_cursor:
        note = None
        gpu_models = []
        active_provider_obj = {"address": active_provider["owner"], "url": active_provider["host_uri"],
                               "praetor": active_provider["praetor"]}

        if active_provider["host_uri"] not in unique_host_uris:
            unique_host_uris.append(active_provider["host_uri"])
        else:
            active_provider_obj["status"] = False
            inactive_providers.append(active_provider_obj)
            continue

        note_data = active_provider["note"] if "note" in active_provider else None
        if note_data is not None and (note_data["start_time"] <= current_time <= note_data["end_time"]):
            note = note_data["message"]

        provider_cluster_detail = calculate_provider_resources_v31(active_provider["manifest"],
                                                                   active_provider["bidengine"],
                                                                   active_provider["cluster"],
                                                                   active_provider["cluster_public_hostname"])

        active_provider_obj["status"] = active_provider["connected"]
        active_provider_obj["created"] = active_provider["created"]

        active_provider_obj["uptime"] = (active_provider["online_history"].count(True) /
                                         len(active_provider["online_history"])) * 100
        active_provider_obj["attributes"] = active_provider["attributes"]
        for attribute in active_provider_obj["attributes"]:
            if "capabilities/gpu/vendor" in attribute["key"] and "true" in attribute["value"]:
                gpu_models.append(attribute["key"].split("/")[-1])
        if len(gpu_models) > 0:
            active_provider_obj["gpu_models"] = gpu_models
            active_gpus = provider_cluster_detail["active_resources"]["gpu"] if "gpu" in provider_cluster_detail["active_resources"] else 0
            available_gpus = provider_cluster_detail["available_resources"]["gpu"] if "gpu" in provider_cluster_detail["available_resources"] else 0
            pending_gpus = provider_cluster_detail["pending_resources"]["gpu"] if "gpu" in provider_cluster_detail["pending_resources"] else 0
            active_provider_obj["total_gpus"] = active_gpus + available_gpus + pending_gpus
            if "total_gpus" in active_provider_obj and active_provider_obj["total_gpus"] > 0:
                active_provider_obj["gpu_provider"] = True
        active_provider_obj["info"] = active_provider["info"]
        active_provider_obj["online_history"] = active_provider["online_history"][-10:]
        active_provider_obj["provider_note"] = note
        active_provider_obj["provider_location"] = active_provider["provider_location"] \
            if "provider_location" in active_provider else None

        active_provider_obj.update(provider_cluster_detail)
        active_providers.append(active_provider_obj)

    inactive_providers_cursor = providers_collection.find({"connected": False, "chainid": chain_id}, {"_id": 0},
                                                          sort=[("praetor", -1)])
    for inactive_provider in inactive_providers_cursor:
        note = None
        gpu_models = []
        note_data = inactive_provider["note"] if "note" in inactive_provider else None
        if note_data is not None and (note_data["start_time"] <= current_time <= note_data["end_time"]):
            note = note_data["message"]

        inactive_provider_obj = {"address": inactive_provider["owner"], "url": inactive_provider["host_uri"],
                                 "status": inactive_provider["connected"],
                                 "online_history": inactive_provider["online_history"][-10:],
                                 "praetor": inactive_provider["praetor"], "provider_note": note,
                                 "created": inactive_provider["created"],
                                 "provider_location": inactive_provider["provider_location"] if "provider_location" in inactive_provider else None}

        for attribute in inactive_provider["attributes"]:
            if "capabilities/gpu/vendor" in attribute["key"] and "true" in attribute["value"]:
                gpu_models.append(attribute["key"].split("/")[-1])
        if len(gpu_models) > 0:
            inactive_provider_obj["gpu_provider"] = True
            inactive_provider_obj["gpu_models"] = gpu_models

        inactive_providers.append(inactive_provider_obj)

    providers = {
        "count": {
            "active": len(active_providers),
            "inactive": len(inactive_providers),
            "total": len(active_providers) + len(inactive_providers)
        },
        "providers": {
            "active_providers": active_providers,
            "inactive_providers": inactive_providers
        }
    }
    return providers


def get_provider(search_query, fields=None):
    select_fields = {field: 1 for field in fields} if fields is not None else None
    return providers_collection.find_one(search_query, select_fields)


def get_provider_note(wallet_address: str):
    provider = get_provider({"owner": wallet_address}, ["note"])
    if provider is not None and "note" in provider:
        return provider["note"]
    else:
        return None


def update_provider_note(wallet_address: str, note_obj: dict):
    # Update provider note object for wallet address
    update_provider({"owner": wallet_address}, {"$set": {"note": note_obj}})


def delete_provider_note(wallet_address: str):
    # Delete provider note object for wallet address
    providers_collection.update_one({"owner": wallet_address}, {"$unset": {"note": 1}})
