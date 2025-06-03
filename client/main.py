import logging
import os
import sqlite3
import uvicorn
import dynaconf
from routers.certs import router_certificate
from routers.message import message_router
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse

from fastapi import FastAPI, HTTPException, Request


logging.basicConfig(level=0)


app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


conf = dynaconf.Dynaconf(settings_files="config.toml")
app.state.recv_msg = "Нет сообщений"
app.state.recv_check = "Нечего проверять"
app.include_router(router_certificate, tags=["certs"])
app.include_router(message_router, tags=["message"])


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "mess": request.app.state.recv_msg,
            "check": request.app.state.recv_check,
        },
    )


uvicorn.run(app, host="0.0.0.0", port=8000)
