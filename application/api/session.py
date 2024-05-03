from fastapi import APIRouter, Depends, BackgroundTasks

from application.exception.praetor_exception import PraetorException
from application.data.session import get_stage_and_process_step
from application.utils.cache import delete_object
from application.utils.dependency import verify_token
from application.utils.general import success_response, error_response
from application.utils.logger import log

router = APIRouter()


@router.get("/session/{session_id}/{event_type}", dependencies=[Depends(verify_token)])
async def session_get(session_id: str, event_type: str):
    log.info(f"Get process from database for session id({session_id}) and event type({event_type})")
    try:
        if event_type.lower() != "k3s" and event_type.lower() != "provider":
            raise PraetorException("Event type is not valid", "P5009")

        process_name = "k3s_process" if event_type == "k3s" else "provider_process"

        # Fetch process details from database
        session_detail = get_stage_and_process_step(session_id, process_name)

        return success_response({"stage": session_detail["stage"], "process": session_detail[process_name]})
    except PraetorException as pe:
        delete_object(session_id)
        return error_response(pe.error_code, pe.payload)
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while getting process from database of the session id({session_id}) - {e}")
        raise e


@router.get("/session/logout/{session_id}", dependencies=[Depends(verify_token)])
async def session_logout_get(background_tasks: BackgroundTasks, session_id: str):
    try:
        log.info(f"Logged out for session id({session_id})")

        # Remove session from redis
        background_tasks.add_task(delete_object, session_id)

        return success_response("Session logged out successfully")
    except PraetorException as pe:
        delete_object(session_id)
        return error_response(pe.error_code, pe.payload)
    except Exception as e:
        delete_object(session_id)
        log.error(f"Error while logged out of the session id({session_id}) - {e}")
        raise e
