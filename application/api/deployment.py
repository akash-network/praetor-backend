from fastapi import APIRouter, Depends
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException

from application.config.config import Config
from application.exception.praetor_exception import PraetorException
from application.service.chain import get_latest_block
from application.service.deployment import fetch_deployments_by_provider, fetch_deployment_details
from application.utils.cache import load_object
from application.utils.dependency import verify_token
from application.utils.general import success_response, error_response
from application.utils.logger import log

router = APIRouter()


@router.get("/deployment/list/{offset}/{limit}/{status}")
async def provider_deployments_get(offset: int, limit: int, status: str, wallet_address: str = Depends(verify_token)):
    try:

        deployments = fetch_deployments_by_provider(wallet_address, offset, limit, status)

        return success_response(deployments)
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Deployments list unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while fetching deployments for provider ({wallet_address})- {e}")
        raise e


@router.get("/deployment/latest/block")
async def deployment_latest_block_get(wallet_address: str = Depends(verify_token)):
    try:
        log.info(f"Get latest block for provider - {wallet_address}")

        # load session object for connection
        app_session_id = Config.APP_SESSION_ID
        ssh_client = load_object(app_session_id)
        latest_block = get_latest_block(ssh_client)

        return success_response(latest_block)
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Latest block unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while fetching latest block for provider ({wallet_address})- {e}")
        raise e


@router.get("/deployment/details/{owner}/{dseq}")
async def deployment_details_get(owner: str, dseq: str, wallet_address: str = Depends(verify_token)):
    try:
        log.info(f"Get deployment details for provider - {wallet_address} & owner - {owner} & dseq - {dseq}")
        deployments = fetch_deployment_details(wallet_address, owner, dseq)

        # load session object for connection
        app_session_id = Config.APP_SESSION_ID
        ssh_client = load_object(app_session_id)
        latest_block = get_latest_block(ssh_client)

        return success_response({"deployments": deployments, "latest_block": latest_block})
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"Deployment details unexpected exist error - {message}")
        return error_response("P5004", "An Error Occurred! Please try again.")
    except Exception as e:
        log.error(f"Error while fetching deployment details for provider ({wallet_address})- {e}")
        raise e
