import logging
from typing import Optional
from fastapi import APIRouter, Depends, Request, Query
from usecases.dtos import IncomingMessage
from dependencies.db_connection import get_db_connection
from usecases.get_message import get_message_usecase
from usecases.send_mesage import send_message_usecase

message_router = APIRouter(prefix="/message")


@message_router.post("/get_message")
def get_message(request: Request, msg: IncomingMessage):
    return get_message_usecase(request, msg)


@message_router.post("/send_message")
def send_message(
    client_id: int = Query(...),
    msg: str = Query(...),
    override_r: Optional[int] = None,
    override_s: Optional[int] = None,
):
    return send_message_usecase(client_id, msg, override_r, override_s)
