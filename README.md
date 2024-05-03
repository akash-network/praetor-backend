# Praetor-Backend

Welcome to `praetor-backend`, the core REST API logic for the Praetor application, built using FastAPI. This project is designed to handle all the main operational logic and serves as the backbone for managing and processing data efficiently.

## Prerequisites

Before you begin, ensure you have the following installed:

- Python (3.10 or later)
- pip (latest version)

## Installation

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/yourusername/praetor-backend.git
cd praetor-backend
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```

## Configuration

The application relies on various environment variables to control its behavior and integrate with different services. Set these variables in your environment or a `.env` file. Below is a description of each:

```plaintext
# General Application Config
APP_NAME - The name of the application for internal use.
LOG_LEVEL - The verbosity level of logs (e.g., DEBUG, INFO, WARNING, ERROR).
RUN_HIDE - Flag to run some operations in a hidden or stealth mode.
PROVIDER_SYNC_INTERVAL - Interval in seconds for synchronizing provider data.
CACHED_PROVIDER_LIST_NAME - Key name for caching provider list in storage.
CACHED_PROVIDER_TESTNET_LIST_NAME - Key name for caching testnet provider list.
REMOVE_SESSION_INTERVAL - Interval in seconds to check and remove expired sessions.
PRAETOR_FRONTEND_URL - URL of the Praetor frontend application.
EXCLUDED_HOSTNAMES - Comma-separated hostnames to exclude from certain operations.
EXCLUDED_OWNERS - Comma-separated blockchain addresses to exclude from processing.

# MongoDB Config
MONGO_DB_CONNECTION_STRING - MongoDB connection URI.
MONGO_DB_NAME - The database name to use with MongoDB.

# Redis Config
REDIS_URI - URI for connecting to the Redis server.
REDIS_PASSWORD - Password for Redis authentication, if required.
REDIS_PORT - Port number on which the Redis server is running.

# SSH Server Config
PRAETOR_DIR - Directory path where Praetor-related files are stored.
RSA_FILENAME - File name for RSA key.
WALLET_PHRASE_FILENAME - File name for wallet phrases.
WALLET_PASSWORD_FILENAME - File name for wallet passwords.
PROVIDER_CONFIG_FILENAME - Configuration file name for providers.
PRICE_SCRIPT_FILENAME - Script file name for managing provider pricing.

# Akash Server Config
AKASH_HOME - Home directory for Akash configurations.
AKASH_NODE - URL of the main Akash network node.
AKASH_NODE_TESTNET - URL of the Akash testnet node.
AKASH_NODE_STATUS_CHECK - URL to check the status of the main Akash node.
AKASH_NODE_STATUS_CHECK_TESTNET - URL to check the status of the testnet Akash node.
CHAIN_ID - Chain ID of the main Akash network.
CHAIN_ID_TESTNET - Chain ID of the Akash testnet.
KEYRING_BACKEND - Backend for managing cryptographic keys in Akash.
UPLOAD_DIR - Directory to store uploaded files.
KUBE_DIR - Directory to store Kubernetes configurations.
APP_SESSION_ID - Session ID for the app mainnet operations.
APP_SESSION_ID_TESTNET - Session ID for the app testnet operations.
AKASH_VERSION - Version of the Akash software.
AKASH_VERSION_TESTNET - Version of the Akash software for testnet.
ALLOWED_WALLET_ADDRESSES - List of wallet addresses allowed for certain operations.
PROVIDER_SERVICES_VERSION - Version identifier for provider services.
PROVIDER_SERVICES_VERSION_TESTNET - Version identifier for provider services on testnet.
PROVIDER_PRICE_SCRIPT_URL - URL for the provider pricing script.

# Authentication
PUBLIC_KEY - Public key used for authentication procedures.
HOST_NAME - The hostname of the server where the application is running.
SECURITY_HOST - Hostname of the security service.

# Kubernetes
GVISOR_BASE_URL - Base URL for GVisor integration.

# Cloudmos api Config
CLOUDMOS_API_URL - API URL for Cloudmos services.
AVG_BLOCK_PER_MONTH - Average number of blocks per month, used for calculations.
```

## Running the Application

To run the application in development mode, use:

```bash
uvicorn asgi:app --proxy-headers --host 0.0.0.0 --port 80 --reload
```
