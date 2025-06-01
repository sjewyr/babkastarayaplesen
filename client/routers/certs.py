import logging
from fastapi import APIRouter
from usecases.generate_keys import generate_keys_usecase
from client.usecases.all_certs import all_certs_usecase


router_certificate = APIRouter(prefix="/certs")


@router_certificate.post("/generate_keys_and_cert")
def generate_keys():
    return generate_keys_usecase()


@router_certificate.get("/all_certs")
def all_certs():
    return all_certs_usecase()
