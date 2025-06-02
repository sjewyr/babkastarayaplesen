import logging
import os
import sqlite3
import uvicorn
import dynaconf
from routers.certs import router_certificate
from routers.message import message_router

from fastapi import FastAPI


logging.basicConfig(level=0)


app = FastAPI()
conf = dynaconf.Dynaconf(settings_files="config.toml")
app.state.recv_msg = "Нет сообщений"
app.state.recv_check = "Нечего проверять"
app.include_router(router_certificate, tags=["certs"])
app.include_router(message_router, tags=["message"])


uvicorn.run(app, host="0.0.0.0", port=8000)
