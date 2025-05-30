import logging
from fastapi import APIRouter

message_router = APIRouter(prefix="/message")


@message_router.post("/proccess_message")
def proccess_message():
    logging.info("крууууто")
