from pydantic import BaseModel
from typing import Optional


class ResourcesPostRequest(BaseModel):
    session_id: str
    kube_type: Optional[str]
    nodes: Optional[list]
    passphrase: Optional[str]
    ssh_mode: Optional[str]
    control_machine_included: Optional[bool] = False
