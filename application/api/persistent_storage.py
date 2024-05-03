from fastapi import Depends, APIRouter

from application.model.persistent_storage_request import PersistentStorageRequest
from application.service.persistent_storage import get_persistent_drives, update_persistent_drives
from application.utils.cache import delete_object
from application.utils.dependency import verify_token
from application.utils.general import success_response
from application.utils.logger import log

router = APIRouter()


@router.get("/persistent-storage/{session_id}", dependencies=[Depends(verify_token)])
async def persistent_storage_get(session_id: str):
    try:
        # Get persistent storage
        log.info(f"Get persistent storage for session id ({session_id})")

        persistent_drives = get_persistent_drives(session_id)
        return success_response({"drives": persistent_drives})
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while getting persistent storage drives - {e}")
        raise e


@router.post("/persistent-storage", dependencies=[Depends(verify_token)])
async def persistent_storage_post(persistent_storage_request: PersistentStorageRequest):
    try:
        session_id = persistent_storage_request.session_id
        drives = persistent_storage_request.drives

        log.info(f"Update persistent storage for session id ({session_id})")

        storage_types_and_class = update_persistent_drives(session_id, drives)
        return success_response(storage_types_and_class)
    except Exception as e:
        delete_object(persistent_storage_request.session_id)
        log.error(f"Error while persistent storage update - {e}")
        raise e
