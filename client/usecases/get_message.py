import json
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
import pydantic
from usecases.crypto_utils import construct_data_str, custom_hash, check_signature

from usecases.dtos import Certificate, IncomingMessage


def get_message_usecase(request: Request, message: IncomingMessage):
    msg = message.message
    request.app.state.recv_msg = msg
    with open("certs/root_cert.json", "r") as f:
        root_ca = Certificate(**json.load(f))
    with open("certs/ica_cert.json", "r") as f:
        ica_ca = Certificate(**json.load(f))
    with open("certs/client_cert.json") as f:
        data = json.load(f)
        public_keys = data["public_key"]
        private_key = data["private_key"]
        my_cert = data["certificate"]
        my_ca = Certificate(**my_cert)
    if not check_signature(
        message.signature,
        construct_data_str(msg, message.public_keys, message.timestamp),
        message.public_keys[0],
        message.public_keys[1],
    ):
        request.app.state.recv_check = "Подпись сообщения не верна"
        return JSONResponse(
            {"message": msg, "check": "Подпись сообщения не верна"}, 400
        )

    if not check_signature(
        message.certificate.signature,
        construct_data_str(
            message.certificate.subject,
            message.certificate.public_key,
            message.certificate.timestamp,
        ),
        message.certificate.public_key[0],
        message.certificate.public_key[1],
    ):  # Поменять проверку по ключу из наших сертов
        if not check_signature(
            message.ca_ca.signature,
            construct_data_str(
                message.ca_ca.subject, message.ca_ca.public_key, message.ca_ca.timestamp
            ),
            root_ca.public_key[0],
            root_ca.public_key[1],
        ):  # same
            request.app.state.recv_check = "Подпись сертификата УЦ не верна"
            return JSONResponse(
                {"message": msg, "check": "Подпись сертификата УЦ не верна"}, 400
            )
        if not check_signature(
            message.root_ca.signature,
            construct_data_str(
                message.root_ca.subject,
                message.root_ca.public_key,
                message.root_ca.timestamp,
            ),
            root_ca.public_key[0],
            root_ca.public_key[1],
        ):  # same
            request.app.state.recv_check = "Подпись сертификата корневого УЦ не верна"
            return JSONResponse(
                {"message": msg, "check": "Подпись сертификата корневого УЦ не верна"},
                400,
            )

    request.app.state.recv_check = "Подпись верна"
    return JSONResponse({"message": msg, "check": "Подпись верна"})
