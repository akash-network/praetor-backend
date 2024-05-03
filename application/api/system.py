from fastapi import APIRouter, Depends

from application.utils.dependency import verify_token
from application.utils.logger import log

router = APIRouter()


@router.get("/health", dependencies=[Depends(verify_token)])
async def health():
    log.info("Call for health check.")
    return {"ping": "pong"}
