import logging
import os
import sqlite3
import uvicorn
import dynaconf
from routers.register import router_register
from routers.message import message_router

from fastapi import FastAPI

from migrations import migrate

db = sqlite3.connect("data.db")
logging.basicConfig(level=0)

migrate(db)

app = FastAPI()
conf = dynaconf.Dynaconf(settings_files="config.toml")
app.state.db = db
app.include_router(router_register, tags=["register"])
app.include_router(message_router, tags=["message"])


uvicorn.run(app, host=conf.api.host, port=conf.api.port)
