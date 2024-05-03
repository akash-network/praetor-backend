from aenum import MultiValueEnum


class K3sProcess(MultiValueEnum):
    SYSTEM_CHECK = "Checking system", 1
    DEPENDENCIES = "Installing dependencies", 2
    HELM_INSTALL = "Installing helm", 3
    NVIDIA_INSTALL = "Installing nvidia drivers and toolkit", 4
    AKASH_INSTALL = "Installing akash software", 5
    AKASH_HELM_INSTALL = "Installing akash helm repo", 6
    NVIDIA_HELM_INSTALL = "Installing nvidia helm repo", 7
    K3S_INSTALL = "Installing K3S", 8
    COPY_CONFIG = "Moving configuration files", 9
    NODE_LABEL = "Labelling node", 10
    NAMESPACE_CREATE = "Creating namespaces", 11
    HOSTNAME_CREATE = "Creating hostname operator", 12
    INGRESS_CREATE = "Creating nginx ingress", 13
    CREATE_NVIDIA_RUNTIME_CLASS = "Applying NVIDIA runtime engine", 14
    K3S_PROCESS_COMPLETED = "Completed K3S process", 15
