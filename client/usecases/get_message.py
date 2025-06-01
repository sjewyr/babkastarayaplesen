
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
import pydantic
from usecases.crypto_utils import construct_data_str, custom_hash, check_signature

from usecases.dtos import IncomingMessage

def get_message_usecase(request: Request, message: IncomingMessage):
    msg = message.message
    request.app.state.recv_msg = msg
    if not check_signature(message.signature, construct_data_str(msg,message.public_keys, message.timestamp), message.public_keys[0], message.public_keys[1]):
        request.app.state.recv_check = "Подпись сообщения не верна"
        return JSONResponse(400,{"message": msg, "check": "Подпись сообщения не верна"})
        
    if not check_signature(message.certificate, construct_data_str(message.certificate.subject, message.certificate.public_key, message.certificate.timestamp), message.certificate.public_key[0], message.certificate.public_key[1]): # Поменять проверку по ключу из наших сертов
        if not check_signature(message.ca_ca.signature, construct_data_str(message.ca_ca.subject, message.ca_ca.public_key, message.ca_ca.timestamp), message.ca_ca.public_key[0],  message.ca_ca.public_key[0]): # same
            request.app.state.recv_check = "Подпись сертификата УЦ не верна"
            return JSONResponse(400, {"message": msg, "check": "Подпись сертификата УЦ не верна"})
        if not check_signature(message.root_ca.signature, construct_data_str(message.root_ca.subject, message.root_ca.public_key, message.root_ca.timestamp), message.root_ca.public_key[0], message.root_ca.public_key[1]): # same
            request.app.state.recv_check = "Подпись сертификата корневого УЦ не верна"
            return JSONResponse(400, {"message": msg, "check": "Подпись сертификата корневого УЦ не верна"}) 
        
    request.app.state.recv_check = "Подпись верна"
    return JSONResponse({"message": msg, "check": "Подпись верна"})

