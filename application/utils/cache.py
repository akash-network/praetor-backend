import redis
import cloudpickle
from datetime import timedelta

from application.config.config import Config
from application.exception.praetor_exception import PraetorException
from application.utils.remote_client import RemoteClient
from application.utils.ssh_client import SSHClient
from application.utils.logger import log

redis_cache = redis.StrictRedis(
    host=Config.REDIS_URI,
    port=Config.REDIS_PORT,
    password=Config.REDIS_PASSWORD,
    decode_responses=False
)


def cache_object(key: str, remote_client_object: RemoteClient, time: timedelta = None):
    if time is not None:
        redis_cache.set(key, cloudpickle.dumps(remote_client_object), time)
    else:
        redis_cache.set(key, cloudpickle.dumps(remote_client_object))


def cache_providers_list(key: str, providers: dict, time: timedelta = None):
    if time is not None:
        redis_cache.set(key, cloudpickle.dumps(providers), time)
    else:
        redis_cache.set(key, cloudpickle.dumps(providers))


def load_object(key: str):
    try:
        redis_cached_object = redis_cache.get(key)
        if redis_cached_object is None:
            raise PraetorException("Session object not found in cache.", "P4041")

        remote_client_object = cloudpickle.loads(redis_cached_object)
        connection = remote_client_object.connection()
        if remote_client_object.user == "root":
            ssh_client = SSHClient(connection, False)
        else:
            ssh_client = SSHClient(connection, True)
    except PraetorException as pe:
        raise pe
    except Exception as e:
        log.error(f"cloudpickle.loads(remote_connection_object) error: {e}")
        return None

    return ssh_client


def load_provider_list(key: str):
    try:
        redis_cached_object = redis_cache.get(key)
        if redis_cached_object is None:
            raise PraetorException("Provider object not found in cache.", "P4041")

        remote_client_object = cloudpickle.loads(redis_cached_object)

    except PraetorException as pe:
        raise pe
    except Exception as e:
        log.error(f"cloudpickle.loads(remote_connection_object) error: {e}")
        return None

    return remote_client_object


def delete_object(key: str):
    try:
        redis_cache.delete(key)
    except Exception as e:
        log.error(f"Redis error when remove session id {key} and error: {e}")

