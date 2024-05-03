from pydantic import BaseModel


class PersistentStorageRequest(BaseModel):
    session_id: str
    drives: list
