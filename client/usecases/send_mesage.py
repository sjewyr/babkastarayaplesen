import json
import os
import time
from typing import Optional
from fastapi.responses import JSONResponse
import requests

from usecases.crypto_utils import custom_hash, construct_data_str
from usecases.dtos import Certificate, IncomingMessage, Signature


def send_message_usecase(
    client_id: int,
    message: str,
    override_r: Optional[int] = None,
    override_s: Optional[int] = None,
):
    with open("certs/root_cert.json", "r") as f:
        root_ca = Certificate(**json.load(f))
    with open("certs/ica_cert.json", "r") as f:
        ica_ca = Certificate(**json.load(f))
    with open("certs/client_cert.json") as f:
        data = json.load(f)
        public_keys = data["public_key"]
        private_key = data["private_key"]
        cert = data["certificate"]
        my_ca = Certificate(**cert)
    stamp = int(time.time())
    data_str = construct_data_str(message, public_keys, stamp)
    r = custom_hash(data_str, public_keys[1])
    s = pow(r, private_key, public_keys[1])
    sign = Signature(r=r, s=s)
    if override_r and override_s:
        sign = Signature(r=override_r, s=override_s)

    msg = IncomingMessage(
        subject=os.getenv("CLIENT_NAME"),
        message=message,
        signature=sign,
        timestamp=stamp,
        public_keys=public_keys,
        certificate=my_ca,
        root_ca=root_ca,
        ca_ca=ica_ca,
    )
    rs = requests.post(
        url=f"http://client{str(client_id)}:8000/message/get_message",
        json=msg.model_dump(),
    )  # подумать
    return JSONResponse(
        {
            "message": msg.message,
            "check": rs.json()["check"],
            "signature": sign.model_dump(),
        }
    )
