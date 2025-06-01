import pydantic


class Signature(pydantic.BaseModel):
    r: int
    s: int

class Certificate(pydantic.BaseModel):
    subject: str
    issuer: str
    public_key: list[int]
    timestamp: int
    signature: Signature

class IncomingMessage(pydantic.BaseModel):
    subject: str
    message: str
    signature: str
    timestamp: str
    public_keys: list[int]
    signature: Signature
    certificate: Certificate
    root_ca: Certificate
    ca_ca: Certificate 
