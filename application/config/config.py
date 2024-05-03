from os import environ, getenv


class Config:
    # Set application configuration vars from k8s/deployment.yaml file.
    # General Config
    APP_NAME = environ.get("APP_NAME")
    LOG_LEVEL = environ.get("LOG_LEVEL")
    RUN_HIDE = environ.get("RUN_HIDE")
    PROVIDER_SYNC_INTERVAL = environ.get("PROVIDER_SYNC_INTERVAL")
    CACHED_PROVIDER_LIST_NAME = environ.get("CACHED_PROVIDER_LIST_NAME")
    CACHED_PROVIDER_TESTNET_LIST_NAME = environ.get("CACHED_PROVIDER_TESTNET_LIST_NAME")
    REMOVE_SESSION_INTERVAL = environ.get("REMOVE_SESSION_INTERVAL")
    PRAETOR_FRONTEND_URL = environ.get("PRAETOR_FRONTEND_URL")
    EXCLUDED_HOSTNAMES = environ.get("EXCLUDED_HOSTNAMES")
    EXCLUDED_OWNERS = environ.get("EXCLUDED_OWNERS")

    # MongoDB Config
    MONGO_DB_CONNECTION_STRING = environ.get("MONGO_DB_CONNECTION_STRING")
    MONGO_DB_NAME = environ.get("MONGO_DB_NAME")

    # Redis Config
    REDIS_URI = environ.get("REDIS_URI")
    REDIS_PASSWORD = getenv("REDIS_PASSWORD", "")
    REDIS_PORT = int(environ.get("REDIS_PORT"))

    # SSH Server Config
    PRAETOR_DIR = environ.get("PRAETOR_DIR")
    RSA_FILENAME = environ.get("RSA_FILENAME")
    WALLET_PHRASE_FILENAME = environ.get("WALLET_PHRASE_FILENAME")
    WALLET_PASSWORD_FILENAME = environ.get("WALLET_PASSWORD_FILENAME")
    PROVIDER_CONFIG_FILENAME = environ.get("PROVIDER_CONFIG_FILENAME")
    PRICE_SCRIPT_FILENAME = environ.get("PRICE_SCRIPT_FILENAME")

    # Akash Server Config
    AKASH_HOME = environ.get("AKASH_HOME")
    AKASH_NODE = environ.get("AKASH_NODE")
    AKASH_NODE_TESTNET = environ.get("AKASH_NODE_TESTNET")
    AKASH_NODE_STATUS_CHECK = environ.get("AKASH_NODE_STATUS_CHECK")
    AKASH_NODE_STATUS_CHECK_TESTNET = environ.get("AKASH_NODE_STATUS_CHECK_TESTNET")
    CHAIN_ID = environ.get("CHAIN_ID")
    CHAIN_ID_TESTNET = environ.get("CHAIN_ID_TESTNET")
    KEYRING_BACKEND = environ.get("KEYRING_BACKEND")
    UPLOAD_DIR = environ.get("UPLOAD_DIR")
    KUBE_DIR = environ.get("KUBE_DIR")
    APP_SESSION_ID = environ.get("APP_SESSION_ID")
    APP_SESSION_ID_TESTNET = environ.get("APP_SESSION_ID_TESTNET")
    AKASH_VERSION = environ.get("AKASH_VERSION")
    AKASH_VERSION_TESTNET = environ.get("AKASH_VERSION_TESTNET")
    ALLOWED_WALLET_ADDRESSES = environ.get("ALLOWED_WALLET_ADDRESSES").split(",")
    PROVIDER_SERVICES_VERSION = environ.get("PROVIDER_SERVICES_VERSION")
    PROVIDER_SERVICES_VERSION_TESTNET = environ.get("PROVIDER_SERVICES_VERSION_TESTNET")
    PROVIDER_PRICE_SCRIPT_URL = environ.get("PROVIDER_PRICE_SCRIPT_URL")

    # Authentication
    PUBLIC_KEY = environ.get("PUBLIC_KEY")
    HOST_NAME = environ.get("HOST_NAME")
    SECURITY_HOST = environ.get("SECURITY_HOST")

    # Kubernetes
    GVISOR_BASE_URL = environ.get("GVISOR_BASE_URL")

    # Cloud-mos api Config
    CLOUDMOS_API_URL = environ.get("CLOUDMOS_API_URL")
    AVG_BLOCK_PER_MONTH = environ.get("AVG_BLOCK_PER_MONTH")
