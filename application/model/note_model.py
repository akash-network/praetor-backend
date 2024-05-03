from pydantic import BaseModel


class NoteRequest(BaseModel):
    message: str
    start_time: int
    end_time: int
