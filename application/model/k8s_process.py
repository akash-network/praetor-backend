from aenum import MultiValueEnum


class K8sProcess(MultiValueEnum):
    START_K8S_PROCESS = "Start kubespray process", 1
    NVIDIA_INSTALL = "Installing nvidia drivers and toolkit", 2
    KUBESPRAY_INSTALL = "Install kubespray dependencies", 3
    PREPARE_ANSIBLE = "Prepare for ansible build", 4
    CONFIGURE_NVIDIA = "Configure NVIDIA", 5
    RUN_ANSIBLE = "Run ansible playbook", 6
    KUBE_FILE_CONFIGURE = "Configure kube config file", 7
    NVIDIA_HELM_INSTALL = "Installing nvidia helm repo", 8
    NODE_LABEL = "Label node", 9
    NAMESPACE_CREATE = "Create namespaces", 10
    HOSTNAME_CREATE = "Create hostname operator", 11
    INGRESS_CREATE = "Create nginx ingress", 12
    CREATE_NVIDIA_RUNTIME_CLASS = "Applying NVIDIA runtime engine", 13
    PERSISTENT_STORAGE = "Create persistent storage", 14
    PROVIDER_CHECK = "Check system for akash provider", 15
    PROVIDER_UPDATE = "Update on chain provider", 16
    CERTIFICATE_CREATE = "Create on chain TLS certificate", 17
    SCRIPT_FILE_CREATE = "Create script file", 18
    INSTALL_PROVIDER_HELM = "Installing provider helm chart", 19
    PROVIDER_PROCESS_COMPLETED = "Complete provider process", 20
    K8S_PROCESS_COMPLETED = "Complete K8S process", 21
