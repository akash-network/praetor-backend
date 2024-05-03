import json
from fastapi import APIRouter, Depends, UploadFile, File, Form
from invoke.exceptions import UnexpectedExit
from json import JSONDecodeError
from paramiko.ssh_exception import AuthenticationException
from typing import Optional

from application.exception.praetor_exception import PraetorException
from application.service.k8s import validate_nodes_connection
from application.utils.cache import load_object, delete_object
from application.utils.dependency import verify_token
from application.utils.general import success_response, error_response
from application.utils.logger import log

router = APIRouter()


@router.post("/k8s", dependencies=[Depends(verify_token)])
async def k8s_post(nodes: str = Form(...), session_id: str = Form(...),
                   control_machine_included: Optional[bool] = Form(False),
                   key_file: Optional[UploadFile] = File(None), passphrase: Optional[str] = Form(None)):
    try:
        # Check nodes connectivity
        log.info(f"Check nodes connectivity for session id ({session_id})")
        try:
            nodes = json.loads(nodes)
            log.info(f"Nodes object found, {nodes}")
        except JSONDecodeError:
            log.error(f"Nodes is not a valid json object. {nodes}")
            raise PraetorException("Invalid nodes request", "P4044")

        ssh_client = load_object(session_id)
        nodes_response, status, ingress_ip = validate_nodes_connection(ssh_client, nodes, session_id, key_file,
                                                                       passphrase, control_machine_included)
        if status is True:
            return success_response({"node_connection": nodes_response, "ingress_ip": ingress_ip})
        else:
            return error_response("P50023", {"node_connection": nodes_response})
    except AuthenticationException:
        delete_object(session_id)
        return error_response("P4016", "Authentication failed, please verify your provider details.")
    except OSError as oe:
        delete_object(session_id)
        raise oe
    except PraetorException as pe:
        delete_object(session_id)
        return error_response(pe.error_code, pe.payload)
    except UnexpectedExit as ue:
        delete_object(session_id)
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"K8S unexpected exist error - {message}")
        return error_response("P5019", "An Error Occurred! Please try again.")
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while installing k8s for wallet address()- {e}")
        raise e
