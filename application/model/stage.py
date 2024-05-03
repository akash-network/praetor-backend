from enum import Enum


class Stage(Enum):
    NODE_VERIFIED = "Node Verified"

    SYSTEM_CHECK = "Checking system"
    DEPENDENCIES = "Installing dependencies"
    HELM_INSTALL = "Installing helm"
    NVIDIA_INSTALL = "Installing nvidia drivers and toolkit"
    AKASH_INSTALL = "Installing akash software"
    AKASH_HELM_INSTALL = "Installing akash helm repo"
    NVIDIA_HELM_INSTALL = "Installing nvidia helm repo"
    K3S_INSTALL = "Installing K3S"
    NODE_LABEL = "Labelling node"
    NAMESPACE_CREATE = "Creating namespaces"
    HOSTNAME_CREATE = "Creating hostname operator"
    INGRESS_CREATE = "Creating nginx ingress"
    CONFIGURE_NVIDIA = "Configure NVIDIA"
    CREATE_NVIDIA_RUNTIME_CLASS = "Applying NVIDIA runtime engine"
    COPY_CONFIG = "Moving configuration files"
    K3S_PROCESS_COMPLETED = "Completed K3S process"

    CRD_INSTALL = "Installing custom resource definitions"
    NETWORK_POLICY = "Applying network policies"
    PERSISTENT_STORAGE = "Create persistent storage"
    K3S_ERROR = "Error while installing K3S"

    WALLET_IMPORTED = "Wallet Imported"

    KUBE_CONFIGURED = "Kubernetes Configured"

    PROVIDER_CHECK = "Checking system for akash provider"
    PROVIDER_CREATE = "Creating on chain provider"
    PROVIDER_UPDATE = "Updating on chain provider"
    CERTIFICATE_CREATE = "Creating on chain TLS certificate"
    SCRIPT_FILE_CREATE = "Creating script file"
    SERVICE_FILE_CREATE = "Creating service file"
    PROVIDER_SERVICE_START = "Starting akash provider service"
    PROVIDER_PROCESS_COMPLETED = "Completed provider process"
    INSTALL_PROVIDER_HELM = "Installing provider helm chart"
    PROVIDER_ERROR = "Error while creating provider service"

    START_K8S_PROCESS = "Start kubespray process"
    KUBESPRAY_INSTALL = "Install kubespray dependencies"
    PREPARE_ANSIBLE = "Prepare for ansible build"
    RUN_ANSIBLE = "Run ansible playbook"
    KUBE_FILE_CONFIGURE = "Configure kube config file"
    K8S_PROCESS_COMPLETED = "Complete K8S process"
    K8S_ERROR = "Error while installing K8S"
