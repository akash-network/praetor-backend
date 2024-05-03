from fastapi import APIRouter, BackgroundTasks, Depends
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException

from application.config.config import Config
from application.data.session import update_provider_request, get_kube_build, get_chain_id
from application.exception.praetor_exception import PraetorException
from application.model.provider_model import ProviderPostRequest
from application.model.resource_model import ResourcesPostRequest
from application.service.common import check_on_chain_provider_status, check_on_chain_provider_service_status, \
    get_active_process
from application.service.k8s import build_k8s_with_kubespray
from application.service.provider import provider_services, get_resources_from_nodes, \
    get_resources_from_kube
from application.utils.cache import load_object, load_provider_list, delete_object
from application.utils.dependency import verify_token
from application.utils.general import error_response, success_response
from application.utils.logger import log

router = APIRouter()


@router.post("/provider")
async def provider_post(background_tasks: BackgroundTasks, provider_request: ProviderPostRequest,
                        wallet_address: str = Depends(verify_token)):
    session_id = provider_request.session_id
    try:
        domain_name = provider_request.domain_name
        attributes = provider_request.attributes
        persistent_type = provider_request.persistent_type
        per_unit_prices = {
            "cpu": provider_request.bid_price_cpu_scale,
            "memory": provider_request.bid_price_memory_scale,
            "storage": provider_request.bid_price_storage_scale,
            "pres_hdd": provider_request.bid_price_hd_pres_hdd_scale,
            "pres_ssd": provider_request.bid_price_hd_pres_ssd_scale,
            "pres_nvme": provider_request.bid_price_hd_pres_nvme_scale,
            "endpoint": provider_request.bid_price_endpoint_scale,
            "ip": provider_request.bid_price_ip_scale,
            "gpu": provider_request.bid_price_gpu_scale
        }

        kube_build = get_kube_build(session_id)
        chain_id = get_chain_id(session_id)
        if kube_build is None:
            PraetorException("Kube build object does not exist for session id", "P4045")
        kube_status = kube_build["status"]
        kube_type = kube_build["type"]

        ssh_client = load_object(session_id)

        provider_request_dict = vars(provider_request)
        provider_request_dict["provider_ip"] = str(ssh_client.connection.host)
        update_provider_request(session_id, provider_request_dict)

        if kube_status is False or (kube_status is True and kube_type == "k3s"):
            background_tasks.add_task(provider_services, ssh_client, session_id, domain_name, attributes,
                                      wallet_address, persistent_type, per_unit_prices)
        elif kube_status is True and kube_type == "k8s":
            background_tasks.add_task(build_k8s_with_kubespray, ssh_client, session_id, domain_name, attributes,
                                      wallet_address, persistent_type, per_unit_prices, chain_id)
        return success_response("Provider services are running in background.")
    except AuthenticationException:
        delete_object(session_id)
        return error_response("P4013", "Authentication failed, please verify your provider details.")
    except PraetorException as pe:
        delete_object(session_id)
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        delete_object(session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Provider unexpected exist error - {message}")
        return error_response("P5003", "An Error Occurred! Please try again.")
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while creating provider for session id({session_id})- {e}")
        raise e


@router.get("/provider/status")
async def provider_status_get(chainid: str, wallet_address: str = Depends(verify_token)):
    log.info(f"Getting wallet address ({wallet_address})")
    try:
        app_session_id = Config.APP_SESSION_ID if chainid == Config.CHAIN_ID else Config.APP_SESSION_ID_TESTNET
        ssh_client = load_object(app_session_id)

        provider_details = check_on_chain_provider_status(ssh_client, wallet_address, chainid)
        provider_online_status = check_on_chain_provider_service_status(ssh_client, wallet_address, chainid)
        active_process_status = get_active_process(wallet_address)

        return success_response({"provider": False if provider_details is False else provider_details,
                                 "online": False if provider_online_status is False else True,
                                 "active_process": active_process_status})
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Provider unexpected exist error - {message}")
        return error_response("P5003", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while fetching provider detail for wallet address ({wallet_address})- {e}")
        raise e


@router.get("/list-providers")
async def provider_get(chainid: str):
    log.info(f"Get providers")
    try:
        provider_list_name = Config.CACHED_PROVIDER_LIST_NAME if chainid == Config.CHAIN_ID \
            else Config.CACHED_PROVIDER_TESTNET_LIST_NAME

        providers = load_provider_list(provider_list_name)
        return success_response(providers)
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Provider unexpected exist error - {message}")
        return error_response("P5003", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while fetching providers - {e}")
        raise e


@router.get("/providers")
async def provider_get(chainid: str = Config.CHAIN_ID, wallet_address: str = Depends(verify_token)):
    log.info(f"Get providers list")
    try:
        if wallet_address not in Config.ALLOWED_WALLET_ADDRESSES:
            return error_response("P4032", "You are not authorized to get the providers list.")

        provider_list_name = Config.CACHED_PROVIDER_LIST_NAME if chainid == Config.CHAIN_ID \
            else Config.CACHED_PROVIDER_TESTNET_LIST_NAME
        providers = load_provider_list(provider_list_name)

        return success_response(providers)
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Provider unexpected exist error - {message}")
        return error_response("P5003", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while fetching providers - {e}")
        raise e


@router.post("/provider/resources", dependencies=[Depends(verify_token)])
async def nodes_details(resources_request: ResourcesPostRequest):
    try:
        session_id = resources_request.session_id
        ssh_client = load_object(session_id)

        kube_build = get_kube_build(session_id)
        if kube_build is None:
            PraetorException("Kube build object does not exist for session id", "P4045")
        kube_status = kube_build["status"]
        kube_type = kube_build["type"]

        resources = {}
        if kube_status is False or (kube_status is True and kube_type == "k3s"):
            resources = get_resources_from_kube(ssh_client)
        elif kube_status is True and kube_type == "k8s":
            resources = get_resources_from_nodes(ssh_client, session_id, resources_request.nodes,
                                                 resources_request.passphrase, resources_request.ssh_mode,
                                                 resources_request.control_machine_included)

        return success_response({"resources": resources})
    except AuthenticationException as ae:
        delete_object(resources_request.session_id)
        raise ae
    except UnexpectedExit as ue:
        delete_object(resources_request.session_id)
        raise ue
    except Exception as e:
        delete_object(resources_request.session_id)
        raise e
