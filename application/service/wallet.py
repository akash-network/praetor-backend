import json
from invoke import Responder
from paramiko.ssh_exception import AuthenticationException
from invoke.exceptions import UnexpectedExit

from application.config.config import Config
from application.data.session import update_session_stage, update_session_logs
from application.exception.praetor_exception import PraetorException
from application.model.stage import Stage
from application.service.common import get_passphrase
from application.utils.logger import log
from application.utils.ssh_client import SSHClient


def auto_import_wallet(ssh_client: SSHClient, wallet_request, wallet_address: str):
    try:
        if wallet_request.wallet_phrase is None or wallet_request.wallet_phrase == "":
            raise PraetorException("Wallet import seed phrase parameter is not valid", "P5010")

        if wallet_request.password is None or wallet_request.password == "":
            raise PraetorException("Wallet import password parameter is not valid", "P5011")

        log.info(f"Decrypt the wallet phrase for address({wallet_address})")
        # Decrypt the wallet phrase
        _decrypt_wallet_phrase(ssh_client, wallet_request.session_id, wallet_request.wallet_phrase)
        log.info(f"Decrypt the wallet password for address({wallet_address})")
        # Decrypt the wallet password
        _decrypt_wallet_password(ssh_client, wallet_request.session_id, wallet_request.password)

        log.info(f"add keyring files in the server using passphrase and password for further use of network")
        # keys add for akash network to authenticate
        _akash_key_add(ssh_client, wallet_request.session_id, wallet_request.override_seed)
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        error_message = ue.result.stderr if ue.result.stderr != "" else ue.result.stdout
        if f"account with address {wallet_address} already exists in keyring, delete the key" in str(error_message):
            log.info(f"Warning: the key already exist. So, skip the import")
            return True
        else:
            raise ue
    except Exception as e:
        raise e


def _decrypt_wallet_phrase(ssh_client: SSHClient, session_id: str, wallet_phrase: str):
    try:
        rsa_file_path = f"{Config.PRAETOR_DIR}/{Config.RSA_FILENAME}"
        wallet_phrase_path = f"{Config.PRAETOR_DIR}/{Config.WALLET_PHRASE_FILENAME}"

        # Create Wallet Phrase file with encrypted public key
        ssh_client.run(f"echo {wallet_phrase} | base64 --decode >| {wallet_phrase_path}.enc")
        # Decrypt Private key using Wallet Phrase file
        ssh_client.run(f"openssl pkeyutl -decrypt -inkey {rsa_file_path} -passin pass:{session_id} "
                       f"-in {wallet_phrase_path}.enc -out {wallet_phrase_path}.txt")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _decrypt_wallet_password(ssh_client: SSHClient, session_id: str, wallet_password: str):
    try:
        rsa_file_path = f"{Config.PRAETOR_DIR}/{Config.RSA_FILENAME}"
        wallet_password_path = f"{Config.PRAETOR_DIR}/{Config.WALLET_PASSWORD_FILENAME}"

        # Create Wallet Password file with encrypted public key
        ssh_client.run(f"echo {wallet_password} | base64 --decode >| {wallet_password_path}.enc")
        # Decrypt Private key using Wallet Password file
        ssh_client.run(f"openssl pkeyutl -decrypt -inkey {rsa_file_path} -passin pass:{session_id} "
                       f"-in {wallet_password_path}.enc -out {wallet_password_path}.txt")
    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def _akash_key_add(ssh_client: SSHClient, session_id: str, override_seed: bool):
    wallet_phrase_path = f"{Config.PRAETOR_DIR}/{Config.WALLET_PHRASE_FILENAME}"
    wallet_password_path = f"{Config.PRAETOR_DIR}/{Config.WALLET_PASSWORD_FILENAME}"
    try:
        if override_seed:
            ssh_client.run(f"rm -rf {Config.AKASH_HOME}/keyring-file")

        # get mnemonic seed phrase from the file to inject in subsequent command
        phrase_result = ssh_client.run(f"cat {wallet_phrase_path}.txt", hide=True)
        mnemonic = phrase_result.stdout

        # get passphrase from the file to inject in subsequent command
        passphrase = get_passphrase(ssh_client)

        # create input prompts for mnemonic and passphrase for keyring
        y = "y"
        bip39_mnemonic = Responder(pattern=f"> Enter your bip39 mnemonic", response=f"{mnemonic}\n")
        key_phrase_passphrase = Responder(pattern=f"Enter keyring passphrase:", response=f"{passphrase}\n")
        re_key_phrase_passphrase = Responder(pattern=f"Re-enter keyring passphrase:", response=f"{passphrase}\n")
        override = Responder(pattern=f"override the existing name .*:", response=f"{y}\n")

        # add final keyring files in akash home folder(default)
        ssh_client.run(f"~/bin/provider-services --keyring-backend file keys add {session_id} --recover", pty=True,
                       hide=True, watchers=[bip39_mnemonic, key_phrase_passphrase, re_key_phrase_passphrase, override])

        # updated the session stage for given session id
        update_session_stage(session_id, Stage.WALLET_IMPORTED)
        update_session_logs(session_id, f"Wallet Imported for address:({session_id})")

    except AuthenticationException as ae:
        raise ae
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e
    finally:
        # Remove wallet phrase file
        ssh_client.run(f"rm -rf {wallet_phrase_path}.txt {wallet_phrase_path}.enc {wallet_password_path}.enc")


def check_valid_phrase(ssh_client: SSHClient, wallet_address: str):
    try:
        # Check wallet password file exist or not
        log.info(f"Check wallet password file exist for address({wallet_address})")
        wallet_password_path = f"{Config.PRAETOR_DIR}/{Config.WALLET_PASSWORD_FILENAME}.txt"
        file_exist = ssh_client.run(f"[ -f {wallet_password_path} ] && echo 'yes' || echo 'no' ", hide=True)
        if file_exist.stdout == 'no':
            raise PraetorException("Wallet password file not found", "P4043")

        # get passphrase from the file to inject in subsequent command
        ssh_client.run(f"cat {wallet_password_path} | tee {Config.PRAETOR_DIR}/key-pass.txt", hide=True)
        ssh_client.run(f"echo >> {Config.PRAETOR_DIR}/key-pass.txt")

        password_result = ssh_client.run(f"cat {wallet_password_path}", hide=True)
        passphrase = password_result.stdout

        key_phrase_passphrase = Responder(pattern=f"Enter keyring passphrase:", response=f"{passphrase}\n")

        # Check wallet phrase to match wallet address
        result = ssh_client.run(f"~/bin/provider-services keys show {wallet_address} "
                                f"--keyring-backend {Config.KEYRING_BACKEND} -a",
                                pty=True, watchers=[key_phrase_passphrase], hide=True)
        if result.failed is False:
            keyring_address = result.stdout.split("\n")[1].replace("\r", "")
            if wallet_address != keyring_address:
                ssh_client.run(f"~/bin/provider-services keys delete {wallet_address} --keyring-backend "
                               f"{Config.KEYRING_BACKEND} --yes", pty=True, watchers=[key_phrase_passphrase])
                raise PraetorException("Wallet address and seed phrase does not match.", "P5006")

    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e


def export_wallet(ssh_client: SSHClient, wallet_address: str):
    try:
        ssh_client.run(f"rm -rf {Config.PRAETOR_DIR}/key.pem")

        # get passphrase
        passphrase = get_passphrase(ssh_client)
        # create input prompts for passphrase for keyring
        export_passphrase_prompt = Responder(pattern=f"Enter passphrase to encrypt the exported key:",
                                             response=f"{passphrase}\n")
        passphrase_prompt = Responder(pattern=f"Enter keyring passphrase:", response=f"{passphrase}\n")

        # List all keys
        keys_result = ssh_client.run(f"~/bin/provider-services keys list --keyring-backend {Config.KEYRING_BACKEND} "
                                     f"--output json", pty=True, watchers=[passphrase_prompt])
        keys = json.loads(keys_result.stdout.split("\n")[1].replace("\r", ""))

        key_name = wallet_address
        for key in keys:
            if key["address"] == wallet_address:
                key_name = key["name"]
                break

        # Export wallet
        private_key_result = ssh_client.run(f"~/bin/provider-services keys export {key_name} "
                                            f"--keyring-backend {Config.KEYRING_BACKEND}",
                                            pty=True, watchers=[passphrase_prompt, export_passphrase_prompt], hide=True)
        start_str = '-----BEGIN TENDERMINT PRIVATE KEY-----'
        end_str = '-----END TENDERMINT PRIVATE KEY-----'
        start_idx = private_key_result.stdout.find(start_str)
        end_idx = private_key_result.stdout.find(end_str) + len(end_str)
        private_key = private_key_result.stdout[start_idx:end_idx]
        ssh_client.run(f"""
cat <<EOF | tee {Config.PRAETOR_DIR}/key.pem
{private_key}
EOF
""", pty=True, hide=True)
    except AuthenticationException as ae:
        raise ae
    except PraetorException as pe:
        raise pe
    except UnexpectedExit as ue:
        raise ue
    except Exception as e:
        raise e
