from fastapi import APIRouter, Depends, UploadFile, File, Form, BackgroundTasks
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError
import socket
from typing import Optional

from application.config.config import Config
from application.data.provider import get_provider_note, update_provider_note, delete_provider_note
from application.data.system import get_system_latest_version, check_version_exist_for_upgrade
from application.model.note_model import NoteRequest
from application.data.session import get_active_process_status, get_session_id_for_completed_session, \
    get_provider_request, insert_new_session_data, update_bid_price_session_data, update_provider_url, \
    get_chain_id, update_provider_attributes
from application.exception.praetor_exception import PraetorException
from application.model.dashboard_price_model import DashboardPricePostRequest
from application.model.provider_event_request import ProviderEventRequest, ProviderLogoutRequest
from application.model.version_model import VersionPostRequest
from application.service.akash import get_provider_details
from application.service.dashboard import validate_provider_domain, refresh_provider_list, \
    upgrade_provider_versions, akash_provider_version_by_ssh, restart_provider_pod
from application.service.provider import create_provider_file, get_node_architecture, update_provider_pricing_script
from application.service.ssh import create_ssh_connection, validate_ssh_connection
from application.utils.cache import load_object, delete_object
from application.utils.dependency import verify_token
from application.utils.general import generate_random_string, success_response, error_response
from application.utils.logger import log

router = APIRouter()


@router.get("/dashboard")
async def dashboard_get(chainid: str, wallet_address: str = Depends(verify_token)):
    log.info(f"Getting dashboard details for wallet address - {wallet_address}")
    try:
        # get provider details
        app_session_id = Config.APP_SESSION_ID if chainid == Config.CHAIN_ID else Config.APP_SESSION_ID_TESTNET
        ssh_client = load_object(app_session_id)
        provider_data = get_provider_details(wallet_address, ssh_client, chainid)

        # get session details
        provider_data["session_id"] = get_session_id_for_completed_session(wallet_address)

        return success_response(provider_data)
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Dashboard unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while fetching provider detail on dashboard for wallet address ({wallet_address})- {e}")
        raise e


@router.get("/dashboard/active-process")
async def dashboard_active_process(wallet_address: str = Depends(verify_token)):
    try:
        # get k8s process
        active_process, provider_request = get_active_process_status(wallet_address)
        active_process["provider_detail"] = provider_request
        return success_response(active_process)
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Dashboard unexpected exist error - {message}")
        return error_response("P5004", "Internal server error")
    except Exception as e:
        log.error(f"Error while fetching active process detail for wallet address ({wallet_address})- {e}")
        raise e


@router.get("/dashboard/session/{session_id}", dependencies=[Depends(verify_token)])
async def check_session(session_id: str):
    valid_session = False
    try:
        log.info(f"Checking session id ({session_id}) valid or not...")

        # check session id is valid or not
        ssh_client = load_object(session_id)
        connected = validate_ssh_connection(ssh_client.connection)
        if connected is True:
            log.info(f"Found the valid session.")
            valid_session = True

        return success_response({"valid_session": valid_session})
    except AuthenticationException as ae:
        log.error(f"Authentication exception happened - {ae}")
        return success_response({"valid_session": valid_session})
    except NoValidConnectionsError as ne:
        log.error(f"NoValid connection error - {ne}")
        return success_response({"valid_session": valid_session})
    except PraetorException as pe:
        log.error(f"Praetor exception in dashboard session - {pe}")
        return success_response({"valid_session": valid_session})
    except UnexpectedExit as ue:
        log.error(f"Unexpected exit occurred - {ue}")
        return success_response({"valid_session": valid_session})
    except Exception as e:
        log.error(f"Dashboard session exception - {e}")
        return success_response({"valid_session": valid_session})


@router.post("/dashboard/control-machine")
async def get_dashboard_provider_data(host_name: str = Form(...), port: int = Form(...), user_name: str = Form(...),
                                      password: Optional[str] = Form(None), ssh_mode: str = Form(...),
                                      key_file: Optional[UploadFile] = File(None),
                                      passphrase: Optional[str] = Form(None),
                                      wallet_address: str = Depends(verify_token)):
    try:
        log.info(f"ssh connection request for host - {host_name}, port - {port}, user - {user_name}")
        # get provider details
        if ssh_mode.lower() != "password" and ssh_mode.lower() != "file":
            log.error(f"ssh mode is not valid for dashboard control machine access")
            raise PraetorException("SSH mode must be password or file", "P50026")

        if (ssh_mode.lower() == "file") and (key_file is None or key_file.filename == ""):
            log.error(f"if ssh mode is file then key file can not be null or empty {key_file} for dashboard")
            raise PraetorException("Key file not found", "P50027")

        if (ssh_mode.lower() == "password") and (password is None or password == ""):
            log.error(f"if ssh mode is password then password can not be null or empty for dashboard control machine")
            raise PraetorException("Password is empty", "P50028")

        # generate session id
        session_id = generate_random_string(20)

        # create SSH connection
        if ssh_mode.lower() == "password":
            connection = create_ssh_connection(session_id=session_id, host=host_name, port=port,
                                               user=user_name, password=password)
        else:
            key_file_content = key_file.file.read().decode("utf-8")
            connection = create_ssh_connection(session_id=session_id, host=host_name, port=port, user=user_name,
                                               ssh_key=key_file_content, passphrase=passphrase)

        # validate the ssh connection for the remote client connection
        log.info(f"validating... ssh connection established or not for session id ({session_id})")
        validate_ssh_connection(connection)

        # insert new record in database for new session id
        log.info(f"Inserting new record in database for new session id ({session_id})")
        insert_new_session_data(session_id, wallet_address)

        return success_response({"session_id": session_id})
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Dashboard unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while generating session id in control machine for wallet address ({wallet_address})- {e}")
        raise e


@router.get("/dashboard/provider-bid-price/{session_id}", dependencies=[Depends(verify_token)])
async def get_provider_bid_price_data(session_id: str):
    try:
        log.info(f"Getting provider bid price details for session id - {session_id}")

        # get provider bid price details
        provider_request = get_provider_request(session_id)
        bid_price_data = {}
        if provider_request is not None:
            bid_price_data.update({
                "bid_price_cpu_scale": provider_request["bid_price_cpu_scale"],
                "bid_price_memory_scale": provider_request["bid_price_memory_scale"],
                "bid_price_storage_scale": provider_request["bid_price_storage_scale"],
                "bid_price_hd_pres_hdd_scale": provider_request["bid_price_hd_pres_hdd_scale"]
                if "bid_price_hd_pres_hdd_scale" in provider_request else "0.01",
                "bid_price_hd_pres_ssd_scale": provider_request["bid_price_hd_pres_ssd_scale"]
                if "bid_price_hd_pres_ssd_scale" in provider_request else "0.03",
                "bid_price_hd_pres_nvme_scale": provider_request["bid_price_hd_pres_nvme_scale"]
                if "bid_price_hd_pres_nvme_scale" in provider_request else "0.04",
                "bid_price_endpoint_scale": provider_request["bid_price_endpoint_scale"]
                if "bid_price_endpoint_scale" in provider_request else "0.05",
                "bid_price_ip_scale": provider_request["bid_price_ip_scale"]
                if "bid_price_ip_scale" in provider_request else "5",
                "bid_price_gpu_scale": provider_request["bid_price_gpu_scale"]
                if "bid_price_gpu_scale" in provider_request else "100",
                "bid_deposit": provider_request["bid_deposit"]
            })

        return success_response({"bid_price_data": bid_price_data if len(bid_price_data) > 0 else None,
                                 "session_id": session_id})
    except Exception as e:
        log.error(f"Error while fetching provider bid price detail for session id ({session_id})- {e}")
        raise e


@router.post("/dashboard/provider-bid-price", dependencies=[Depends(verify_token)])
async def provider_bid_price_post(bid_request: DashboardPricePostRequest):
    session_id = bid_request.session_id
    per_unit_prices = {
        "cpu": bid_request.bid_price_cpu_scale,
        "memory": bid_request.bid_price_memory_scale,
        "storage": bid_request.bid_price_storage_scale,
        "pres_hdd": bid_request.bid_price_hd_pres_hdd_scale,
        "pres_ssd": bid_request.bid_price_hd_pres_ssd_scale,
        "pres_nvme": bid_request.bid_price_hd_pres_nvme_scale,
        "endpoint": bid_request.bid_price_endpoint_scale,
        "ip": bid_request.bid_price_ip_scale,
        "gpu": bid_request.bid_price_gpu_scale
    }
    try:
        # load session object for connection
        ssh_client = load_object(session_id)

        chain_id = get_chain_id(session_id)

        # modify bid price on start provider file
        log.info(f"Updating provider bid price detail for session id ({session_id})")
        update_provider_pricing_script(ssh_client, per_unit_prices)

        # Update Price changes in database
        log.info(f"Updating provider bid price details in database for session id ({session_id})")
        update_bid_price_session_data(bid_request)

        # restart pod
        restart_provider_pod(ssh_client, chain_id)
        return success_response("Provider bid price updated successfully")
    except AuthenticationException as ae:
        delete_object(bid_request.session_id)
        raise ae
    except UnexpectedExit as ue:
        delete_object(bid_request.session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Dashboard unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        delete_object(bid_request.session_id)
        log.error(f"Error while updating provider bid price detail for session id ({bid_request.session_id})- {e}")
        raise e


@router.post("/dashboard/provider-event")
async def provider_event_post(event_request: ProviderEventRequest, wallet_address: str = Depends(verify_token)):
    session_id = event_request.session_id
    domain_name = event_request.domain_name
    attributes = event_request.attributes
    modify_event = event_request.modify_event
    try:
        # load session object for connection
        ssh_client = load_object(session_id)

        if modify_event == "domain":
            # Check Provider domain point on valid ip address
            control_machine_ip = socket.gethostbyname(ssh_client.connection.host)
            log.info(f"Checking provider domain (provider.{domain_name}) points on IP ({control_machine_ip}) or not")
            valid_domain = validate_provider_domain(control_machine_ip, f"provider.{domain_name}")
            if valid_domain is False:
                error = f"Provider domain (provider.{domain_name}) is not pointing to the IP ({control_machine_ip})"
                raise PraetorException(f"{error}", "P50029")

        # modify provider details on provider yaml file
        log.info(f"Updating provider {modify_event} detail on provider.yaml file for session id ({session_id})")

        chain_id = get_chain_id(session_id)
        provider_request = get_provider_request(session_id)
        persistent_type = provider_request["persistent_type"] if "provider_type" in provider_request else None
        architecture = get_node_architecture(ssh_client)

        create_provider_file(ssh_client, wallet_address, domain_name, architecture, attributes,
                             persistent_type, True, chain_id, session_id)

        if modify_event == "domain":
            # Provider service restarted
            restart_provider_pod(ssh_client, chain_id)

            # Update Provider domain url in database
            log.info(f"Updating provider {modify_event} in database for session id: {session_id}")
            update_provider_url(session_id, domain_name)
        else:
            # Update Provider attributes in database
            log.info(f"Updating provider {modify_event} in database for session id: {session_id}")
            update_provider_attributes(session_id, attributes)
        return success_response(f"Provider {modify_event} updated successfully")
    except AuthenticationException:
        delete_object(event_request.session_id)
        return error_response("P5004", "An Error Occurred! Please try again.")
    except PraetorException as pe:
        delete_object(event_request.session_id)
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        delete_object(event_request.session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Dashboard unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        delete_object(event_request.session_id)
        log.error(f"Error while updating provider {modify_event} for session id ({session_id})- {e}")
        raise e


@router.get("/dashboard/provider-note")
async def dashboard_provider_note_get(wallet_address: str = Depends(verify_token)):
    try:
        log.info(f"Getting provider note details for the wallet address - {wallet_address}")
        # get provider note details
        provider_note = get_provider_note(wallet_address)

        return success_response({"provider_note": provider_note})
    except Exception as e:
        log.error(f"Error while fetching provider note detail for the wallet address ({wallet_address})- {e}")
        raise e


@router.post("/dashboard/provider-note")
async def dashboard_provider_note_post(background_tasks: BackgroundTasks, notes_request: NoteRequest,
                                       wallet_address: str = Depends(verify_token)):
    try:
        # Update note request changes in database
        log.info(f"Updating provider note details in database for the wallet address: {wallet_address}")

        if notes_request.message.rstrip().lstrip() == "":
            raise PraetorException("Message can not be blank", "P4001")

        update_provider_note(wallet_address, {"message": notes_request.message,
                                              "start_time": notes_request.start_time,
                                              "end_time": notes_request.end_time})
        background_tasks.add_task(refresh_provider_list, Config.CHAIN_ID)

        return success_response("Provider note updated successfully")
    except PraetorException as pe:
        raise (pe.payload, pe.error_code)
    except Exception as e:
        log.error(f"Error while updating provider note detail for the wallet address ({wallet_address})- {e}")
        raise e


@router.delete("/dashboard/provider-note")
async def dashboard_provider_note_delete(background_tasks: BackgroundTasks,
                                         wallet_address: str = Depends(verify_token)):
    try:
        # Removing note request in database
        log.info(f"Removing note from database for the wallet address: {wallet_address}")
        delete_provider_note(wallet_address)

        background_tasks.add_task(refresh_provider_list, Config.CHAIN_ID)

        return success_response("Provider note deleted successfully")
    except Exception as e:
        log.error(f"Error while removing provider note for the wallet address ({wallet_address})- {e}")
        raise e


@router.get("/dashboard/version", dependencies=[Depends(verify_token)])
async def dashboard_version_get(session_id: str):
    try:
        log.info(f"Getting provider version for session_id {session_id}")

        ssh_client = load_object(session_id)
        chain_id = get_chain_id(session_id)

        # get current provider akash version
        provider_version = akash_provider_version_by_ssh(ssh_client)

        # get system latest version of akash
        system_latest_version = get_system_latest_version(chain_id)

        # Check provider version is upgradable or not
        version_upgradable = check_version_exist_for_upgrade(provider_version, chain_id)
        return success_response({"provider_version": provider_version, "system_latest_version": system_latest_version,
                                 "version_upgradable": version_upgradable})

    except AuthenticationException as ae:
        delete_object(session_id)
        raise ae
    except PraetorException as pe:
        delete_object(session_id)
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        delete_object(session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Dashboard fetching provider version unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while fetching provider version for session ({session_id})- {e}")
        raise e


@router.post("/dashboard/version")
async def dashboard_version_post(background_tasks: BackgroundTasks, version_request: VersionPostRequest,
                                 wallet_address: str = Depends(verify_token)):
    try:
        # load session object for connection
        session_id = version_request.session_id
        ssh_client = load_object(session_id)
        chain_id = get_chain_id(session_id)

        # get system latest version of akash
        system_latest_version = get_system_latest_version(chain_id)

        # check each akash versions and upgrade based on exist method
        upgraded_version = system_latest_version
        background_tasks.add_task(upgrade_provider_versions, ssh_client, session_id, version_request.provider_version,
                                  chain_id, wallet_address)

        # Check provider version is upgradable or not
        version_upgradable = check_version_exist_for_upgrade(version_request.provider_version, chain_id)

        return success_response({"provider_version": upgraded_version, "system_latest_version": upgraded_version,
                                 "version_upgradable": version_upgradable})
    except AuthenticationException as ae:
        delete_object(version_request.session_id)
        raise ae
    except PraetorException as pe:
        delete_object(version_request.session_id)
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        delete_object(version_request.session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Dashboard fetching provider version unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        delete_object(version_request.session_id)
        log.error(f"Error while fetching provider version for session id ({version_request.session_id})- {e}")
        raise e


@router.get("/dashboard/restart/{session_id}", dependencies=[Depends(verify_token)])
async def dashboard_restart_get(session_id: str):
    try:
        log.info(f"Restarting provider service pod for session id - {session_id}")

        # load session object for connection
        ssh_client = load_object(session_id)
        chain_id = get_chain_id(session_id)

        # Restart provider pod
        restart_provider_pod(ssh_client, chain_id)

        return success_response("Provider restarted successfully.")
    except AuthenticationException as ae:
        delete_object(session_id)
        raise ae
    except PraetorException as pe:
        delete_object(session_id)
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        delete_object(session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Requesting provider restart error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while requesting provider restart for session id ({session_id})- {e}")
        raise e


@router.post("/dashboard/logout", dependencies=[Depends(verify_token)])
async def dashboard_provider_logout_post(background_tasks: BackgroundTasks, logout_request: ProviderLogoutRequest):
    session_id = logout_request.session_id
    try:
        # Logout Provider service
        log.info(f"Logout provider service for session id - {session_id}")

        if session_id == "":
            raise PraetorException("Session ID can not be blank", "P4002")

        background_tasks.add_task(delete_object, session_id)

        return success_response("Provider logout successfully")
    except PraetorException as pe:
        delete_object(session_id)
        raise (pe.payload, pe.error_code)
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while logout provider for the session id ({session_id})- {e}")
        raise e
