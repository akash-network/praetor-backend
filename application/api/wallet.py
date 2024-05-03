from fastapi import APIRouter, Depends
from paramiko.ssh_exception import AuthenticationException
from invoke.exceptions import UnexpectedExit

from application.data.session import get_installation_status
from application.exception.praetor_exception import PraetorException
from application.model.wallet_model import WalletPostRequest
from application.service.wallet import auto_import_wallet, check_valid_phrase, export_wallet
from application.utils.cache import load_object, delete_object
from application.utils.dependency import verify_token
from application.utils.general import error_response, success_response
from application.utils.logger import log

router = APIRouter()


@router.post("/wallet")
async def wallet_post(wallet_request: WalletPostRequest, wallet_address: str = Depends(verify_token)):
    try:
        # Connect SSH using session id
        ssh_client = load_object(wallet_request.session_id)

        # Check background Dependencies installed or not
        installation_status = get_installation_status(wallet_request.session_id)
        if installation_status is not None and installation_status["status"] is False:
            raise PraetorException(f"An Error Occurred while install dependencies", "P50024")

        if wallet_request.import_mode.lower() != "auto" and wallet_request.import_mode.lower() != "manual":
            raise PraetorException("Wallet import mode must be auto or manual", "P5012")

        if wallet_request.import_mode.lower() == "auto":
            auto_import_wallet(ssh_client, wallet_request, wallet_address)

        log.info(f"Check the wallet address valid for wallet phrase")
        # Check wallet phrase to match wallet address
        check_valid_phrase(ssh_client, wallet_address)

        # Export wallet to key.pem
        export_wallet(ssh_client, wallet_address)

        return success_response("Wallet Imported Successfully.")
    except AuthenticationException:
        delete_object(wallet_request.session_id)
        return error_response("P4012", "Authentication failed, please verify your wallet credentials.")
    except UnexpectedExit as ue:
        delete_object(wallet_request.session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if "public key already exist in keybase" in message:
            return error_response("P4090", "public key already exist in keybase")
        else:
            log.error(f"Wallet unexpected exist error - {message}")
            return error_response("P5002", "An Error Occurred! Please try again.")
    except PraetorException as pe:
        delete_object(wallet_request.session_id)
        return error_response(pe.error_code, pe.payload)
    except Exception as e:
        delete_object(wallet_request.session_id)
        log.error(f"Error while importing wallet for session id({wallet_request.session_id})- {e}")
        raise e
