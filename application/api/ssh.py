import json
import shutil
import socket
from json import JSONDecodeError
from fastapi import APIRouter, Depends, UploadFile, File, Form, BackgroundTasks
from typing import Optional
from invoke.exceptions import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException

from application.data.session import update_kube_build, update_gpu_config
from application.exception.praetor_exception import PraetorException
from application.service.akash import akash_installation
from application.service.common import is_sudo_installed, is_sudo_password_allowed
from application.service.k3s import k3s_installation
from application.service.k8s import k8s_installation
from application.service.ssh import create_ssh_connection, create_rsa_key_pair, configure_kubectl, \
    validate_operating_system, validate_ssh_connection, validate_system_language
from application.utils.dependency import verify_token
from application.utils.general import generate_random_string, success_response, error_response
from application.utils.logger import log
from application.utils.ssh_client import SSHClient

router = APIRouter()


@router.post("/ssh")
async def ssh_post(background_tasks: BackgroundTasks, host_name: str = Form(...), port: int = Form(...),
                   user_name: str = Form(...), password: Optional[str] = Form(None), kube_build: str = Form(...),
                   kube_file: Optional[UploadFile] = File(None), install_akash: Optional[bool] = Form(False),
                   ssh_mode: str = Form(...), key_file: Optional[UploadFile] = File(None),
                   passphrase: Optional[str] = Form(None), chainid: Optional[str] = Form(None),
                   gpu_enabled: Optional[bool] = Form(False), gpu_type: Optional[str] = Form(None),
                   gpu_model: Optional[str] = Form(None),
                   wallet_address: str = Depends(verify_token)):
    try:
        log.info(f"ssh connection request for host - {host_name}, port - {port}, user - {user_name}")

        # validate the kube_build parameter, it must load as valid json
        try:
            kube_build = json.loads(kube_build)
            log.info(f"kube build object found, {kube_build}")
        except JSONDecodeError:
            log.error(f"kube build is not a valid json object. {kube_build}")
            raise PraetorException("Invalid request.", "P4042")

        # validate the kube_build object has the status field
        kube_status = kube_build["status"] if "status" in kube_build else None
        if kube_status is None:
            log.error(f"status attribute is missing in kube build json object. {kube_build}")
            raise PraetorException("Invalid request.", "P4042")

        kube_type = kube_build["type"] if "type" in kube_build else None
        if kube_status is True and kube_type is None:
            log.error(f"type attribute is missing in kube build object when kube status is true. {kube_build}")
            raise PraetorException("Invalid request.", "P4042")

        if kube_status is True and kube_type.lower() != "k3s" and kube_type.lower() != "k8s":
            log.error(f"Kube type install should be either k3s or k8s when kube status is true. {kube_build}")
            raise PraetorException("Invalid request", "P4042")

        # check kube file required or not
        if (kube_status is False) and (kube_file is None or kube_file.filename == ""):
            log.error(f"if kube status is false then kube file can not be null or empty {kube_file}")
            raise PraetorException("Invalid request.", "P4042")

        if kube_status is True and kube_file is not None and kube_file.filename is not None \
                and kube_file.filename != "":
            log.error(f"if kube status is true then kube file should not be provided")
            raise PraetorException("Invalid request", "P4042")

        if ssh_mode.lower() != "password" and ssh_mode.lower() != "file":
            log.error(f"ssh mode is not valid")
            raise PraetorException("SSH mode must be password or file", "P5013")

        if (ssh_mode.lower() == "file") and (key_file is None or key_file.filename == ""):
            log.error(f"if ssh mode is file then key file can not be null or empty {key_file}")
            raise PraetorException("Key file not found", "P5014")

        if (ssh_mode.lower() == "password") and (password is None or password == ""):
            log.error(f"if ssh mode is password then password can not be null or empty")
            raise PraetorException("Password is empty", "P5016")

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
        log.info(f"validating... ssh connection established or not for session id({session_id})")
        validate_ssh_connection(connection)

        # check if the sudo is installed or not
        non_root_sudo_user = False
        if user_name.lower() != "root":
            log.info(f"found non root user, checking sudo package is installed or not")
            sudo_installed = is_sudo_installed(connection)
            if sudo_installed is False:
                raise PraetorException("sudo must be installed if the you want to connect with not root user", "P5019")
            elif sudo_installed is True:
                is_user_sudoer = is_sudo_password_allowed(connection, user_name)
                if is_user_sudoer is False:
                    raise PraetorException("user does not have sudo rights", "P50110")
                elif is_user_sudoer is True:
                    non_root_sudo_user = True

        # ssh client object which will check if the command needs to run with sudoer or not
        ssh_client = SSHClient(connection, non_root_sudo_user)

        # Check system language
        valid_language = validate_system_language(ssh_client)
        if valid_language is False:
            raise PraetorException("System language not supported. It must be english.", "P50030")

        log.info(f"Check operating system for session id ({session_id})")
        # check operating system compatible or not
        operating_system = validate_operating_system(ssh_client, session_id)

        log.info(f"Create RSA Key Pair for session id ({session_id})")
        # create rsa key pair and get the public key
        public_key = create_rsa_key_pair(ssh_client, session_id, wallet_address, chainid)

        update_kube_build(session_id, kube_build)
        update_gpu_config(session_id, {"gpu": gpu_enabled, "type": gpu_type, "model": gpu_model})

        # Upload file and move in physical location if available and check file is correct or not
        if kube_file is not None and kube_file.filename != "":
            log.info(f"Getting kube file with the name, {kube_file.filename}")
            with open(f"./uploads/{session_id}", "wb") as kubefile:
                shutil.copyfileobj(kube_file.file, kubefile)

            # Configure Kubectl
            log.info(f"Configuring Kubectl for session_id ({session_id})")
            configure_kubectl(ssh_client, session_id)

        # Install k3s
        if kube_status is True:
            if kube_type.lower() == "k3s":
                background_tasks.add_task(k3s_installation, ssh_client, session_id, operating_system,
                                          chainid, gpu_enabled, gpu_type, gpu_model)
            else:
                background_tasks.add_task(k8s_installation, ssh_client, session_id, operating_system, chainid)
        else:
            background_tasks.add_task(akash_installation, ssh_client, session_id, install_akash, operating_system)

        return success_response({"session_id": session_id, "public_key": public_key})
    except AuthenticationException:
        return error_response("P4010", "Authentication failed, please verify your ssh credentials.")
    except PraetorException as pe:
        return error_response(pe.error_code, pe.payload)
    except socket.timeout:
        return error_response("P4011", "The connection did not established in given time, "
                                       "please check your credentials and try again.")
    except UnexpectedExit as ue:
        message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        log.error(f"SSH unexpected exist error - {message}")
        return error_response("P5005", "An Error Occurred! Please try again.")
    except Exception as e:
        raise e
