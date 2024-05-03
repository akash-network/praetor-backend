from aenum import MultiValueEnum


class ProviderProcess(MultiValueEnum):
    PROVIDER_CHECK = "Checking system for akash provider", 1
    PROVIDER_UPDATE = "Updating on chain provider", 2
    CERTIFICATE_CREATE = "Creating on chain TLS certificate", 3
    SCRIPT_FILE_CREATE = "Creating script file", 4
    INSTALL_PROVIDER_HELM = "Installing provider helm chart", 5
    PROVIDER_PROCESS_COMPLETED = "Completed provider process", 6
