from pydantic import BaseModel
from typing import Optional


class WalletPostRequest(BaseModel):
    session_id: str
    wallet_phrase: Optional[str]
    password: Optional[str]
    override_seed: Optional[bool] = False
    import_mode: str
