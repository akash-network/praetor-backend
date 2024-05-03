from pydantic import BaseModel


class VersionPostRequest(BaseModel):
    session_id: str
    provider_version: str
