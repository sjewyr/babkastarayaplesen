import logging
from fastapi import APIRouter


router_register = APIRouter(prefix="/register")


@router_register.post("/client")
def register():
    logging.info("Даааа кайфуем")
