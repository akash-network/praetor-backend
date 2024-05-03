from application.config.mongodb import system_collection
from application.config.config import Config


def update_system_detail(search_query: dict, update: dict, upsert: bool = False):
    return system_collection.update_one(search_query, update, upsert=upsert)


def get_system_detail(search_query: dict, fields: list = None, get_internal_id: bool = False):
    select_fields = {field: 1 for field in fields} if fields is not None else None
    select_fields["_id"] = get_internal_id
    return system_collection.find_one(search_query, select_fields)


def get_versions(chain_id: str):
    versions_attribute = "versions" if chain_id == Config.CHAIN_ID else "testnet_versions"
    system = get_system_detail({"app_name": "praetor"}, [versions_attribute])

    if system is not None and versions_attribute in system:
        return system[versions_attribute]
    else:
        return None


def get_system_latest_version(chain_id: str):
    versions_attribute = "versions" if chain_id == Config.CHAIN_ID else "testnet_versions"
    system = get_system_detail({"app_name": "praetor"}, [versions_attribute])

    if system is not None and versions_attribute in system:
        system_versions = system[versions_attribute]
        latest_version = system_versions[-1]
        return latest_version
    else:
        return False


def check_version_exist_for_upgrade(current_version: str, chain_id: str):
    versions_attribute = "versions" if chain_id == Config.CHAIN_ID else "testnet_versions"
    system = get_system_detail({"app_name": "praetor"}, [versions_attribute])

    if system is not None and versions_attribute in system:
        if current_version in system[versions_attribute]:
            return True
        else:
            return False
    else:
        return False
