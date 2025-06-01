import logging
from fastapi import APIRouter, Depends

from dependencies.db_connection import get_db_connection

message_router = APIRouter(prefix="/message")


@message_router.post("/proccess_message")
def proccess_message(db=Depends(get_db_connection)):
    logging.info("крууууто")
