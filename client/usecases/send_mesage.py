import json
import os
import time
import requests

from usecases.crypto_utils import custom_hash
from usecases.dtos import Certificate, IncomingMessage, Signature


def send_message_usecase(client_id: int, message: str):
    public_keys = [65537, 100]  # same
    private_key = 12345
    r = custom_hash(message, public_keys[1])
    s = pow(r, private_key, public_keys[1])
    with open("certs/root_cert.json", "r") as f:
        root_ca = Certificate(**json.load(f))
    with open("certs/ica_cert.json", "r") as f:
        ica_ca = Certificate(**json.load(f))
    with open("certs/client_cert.json") as f:
        my_ca = Certificate(**json.load(f))
    sign = Signature(r=r, s=s)
    msg = IncomingMessage(
        subject=os.getenv("CLIENT_NAME"),
        message=message,
        signature=sign,
        timestamp=int(time.time()),
        public_keys=public_keys,
        certificate=my_ca,
        root_ca=root_ca,
        ca_ca=ica_ca,
    )
    rs = requests.post(
        url=f"http://client{str(client_id)}:8000/message/get_message",
        json=msg.model_dump(),
    )  # подумать
