import requests
from typing import Optional
from paramiko.ssh_exception import AuthenticationException
from application.config.config import Config
from application.exception.praetor_exception import PraetorException
from application.utils.logger import log


def fetch_deployments_by_provider(provider_id: str, offset: int, limit: int, status: Optional[str] = None):
    try:
        if status:
            url = f"{Config.CLOUDMOS_API_URL}/providers/{provider_id}/deployments/{offset}/{limit}?status={status}"
        else:
            url = f"{Config.CLOUDMOS_API_URL}/providers/{provider_id}/deployments/{offset}/{limit}"

        deployments = _get_api_details(url)

        return deployments
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except Exception as e:
        raise e


def fetch_deployment_details(provider_id: str, owner: str, dseq: str):
    try:
        deployment = {}
        leases = []
        avg_block = int(Config.AVG_BLOCK_PER_MONTH)
        url = f"{Config.CLOUDMOS_API_URL}/deployment/{owner}/{dseq}"
        deployment_details = _get_api_details(url)
        valid_deployment = _check_valid_deployment(provider_id, deployment_details["leases"])
        if valid_deployment is False:
            log.error(f"Provider detail not match with lease details - {provider_id}")
            raise PraetorException("Provider cannot access deployment detail.", "P50033")

        if deployment_details:
            if deployment_details["leases"]:
                for lease in deployment_details["leases"]:
                    gseq = lease["gseq"]
                    sequence = gseq - 1
                    eph_storage, per_storage = _get_storage_resources(deployment_details["other"]["groups"][sequence])
                    leases.append({
                        "provider": lease["provider"]["address"],
                        "gseq": gseq,
                        "oseq": lease["oseq"],
                        "price": lease["monthlyCostUDenom"]/avg_block,
                        "createdHeight": lease["createdHeight"],
                        "createdDate": lease["createdDate"],
                        "closedHeight": lease["closedHeight"],
                        "closedDate": lease["closedDate"] if lease["closedHeight"] else None,
                        "status": lease["status"],
                        "resources": {
                            "cpu": lease["cpuUnits"],
                            "memory": lease["memoryQuantity"],
                            "gpu": lease["gpuUnits"],
                            "ephemeralStorage": eph_storage,
                            "persistentStorage": per_storage
                        }
                    })

            balance = deployment_details["other"]["escrow_account"]["balance"]["amount"]
            transferred = deployment_details["other"]["escrow_account"]["transferred"]["amount"]

            deployment.update({
                "owner": owner,
                "dseq": dseq,
                "denom": deployment_details["denom"],
                "createdHeight": deployment_details["createdHeight"],
                "createdDate": deployment_details["createdDate"],
                "closedHeight": deployment_details["closedHeight"],
                "closedDate": deployment_details["closedDate"] if deployment_details["closedHeight"] else None,
                "status": deployment_details["status"],
                "balance": balance,
                "transferred": transferred,
                "total_balance": (float(balance) + float(transferred)),
                "settledAt": deployment_details["other"]["escrow_account"]["settled_at"],
                "leases": leases
            })

            return deployment
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except Exception as e:
        raise e


def _get_api_details(url: str):
    try:
        response = requests.request("GET", url)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            raise PraetorException(response.json(), "P50031")
    except PraetorException as pe:
        raise pe
    except Exception as e:
        raise e


def _check_valid_deployment(provider_id: str, deployment_leases: list):
    try:
        if deployment_leases:
            for lease in deployment_leases:
                if provider_id != lease["provider"]["address"]:
                    return False
        return True
    except Exception:
        return False


def _get_storage_resources(group: dict):
    try:
        ephemeral_storage = 0
        persistent_storage = 0

        if "resources" in group["group_spec"]:
            for resource_detail in group["group_spec"]["resources"]:
                if "storage" in resource_detail["resource"]:
                    for storage in resource_detail["resource"]["storage"]:
                        if storage["name"] == "default":
                            ephemeral_storage += int(storage["quantity"]["val"])
                        if storage["name"] == "data":
                            persistent_storage += int(storage["quantity"]["val"])

        return ephemeral_storage, persistent_storage
    except Exception as e:
        raise e
