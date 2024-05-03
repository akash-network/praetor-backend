from pydantic import BaseModel


class ProviderEventRequest(BaseModel):
    session_id: str
    domain_name: str
    attributes: list
    modify_event: str


class ProviderLogoutRequest(BaseModel):
    session_id: str
