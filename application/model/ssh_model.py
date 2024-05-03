from pydantic import BaseModel


class SSHPostRequest(BaseModel):
    host_name: str
    user_name: str
    password: str
