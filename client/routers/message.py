import logging
from fastapi import APIRouter, Depends

from dependencies.db_connection import get_db_connection
from usecases.get_message import get_message_usecase
from usecases.send_mesage import send_message_usecase

message_router = APIRouter(prefix="/message")


@message_router.post("/get_message")
def get_message(db=Depends(get_db_connection)):
    return get_message_usecase()


@message_router.post("/send_message")
def send_message():
    return send_message_usecase()
