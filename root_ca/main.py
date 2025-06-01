from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import time
import os
import json
import logging
from crypto_utils import generate_keys, custom_hash, construct_data_str

app = FastAPI()

# Настройка логирования
LOG_PATH = os.path.join(os.getcwd(), "data", "logs")
os.makedirs(LOG_PATH, exist_ok=True)
log_file = os.path.join(LOG_PATH, "service.log")

# Очистка лога перед запуском
with open(log_file, 'w'):
    pass

# Настройка логгера
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S,%f'
)

# Хранилище в памяти
keys: dict[str, int] = {}
root_cert: dict = {}

# Директории
CERT_STORE = os.path.join(os.getcwd(), "cert_store")
SIGNED_ICA_DIR = os.path.join(CERT_STORE, "signed_ica_certs")
os.makedirs(SIGNED_ICA_DIR, exist_ok=True)

# Модель запроса
class ICACertRequest(BaseModel):
    subject: str
    public_key: list[int]  # [e, n]
    timestamp: int

@app.post("/generate_keys")
def generate_keys_endpoint():
    p, q, n, e, d = generate_keys()
    keys.update({"p": p, "q": q, "n": n, "e": e, "d": d})
    logging.info(f"Сгенерированы ключи RSA: p={p}, q={q}, n={n}, e={e}, d={d}")
    return {"public_key": [e, n], "private_key": d}

@app.post("/issue_root_cert")
def issue_root_cert():
    if not keys:
        raise HTTPException(status_code=400, detail="Сначала вызовите /generate_keys")
    subject = "Root CA"
    public_key = [keys["e"], keys["n"]]
    timestamp = int(time.time())

    data_str = f"{subject}|{public_key[0]}|{public_key[1]}|{timestamp}"
    r = custom_hash(data_str, keys["n"])
    s = pow(r, keys["d"], keys["n"])

    root_cert.clear()
    root_cert.update({
        "subject": subject,
        "issuer": subject,
        "public_key": public_key,
        "timestamp": timestamp,
        "signature": {"r": r, "s": s}
    })

    path = os.path.join(CERT_STORE, "root_cert.json")
    with open(path, 'w') as f:
        json.dump(root_cert, f, indent=2)

    logging.info(
        f"Выпущен self-signed Root сертификат: subject={subject}, public_key={public_key}, timestamp={timestamp}, r={r}, s={s}"
    )
    return root_cert

@app.get("/send_root_cert")
def send_root_cert():
    if not root_cert:
        raise HTTPException(status_code=404, detail="Root certificate not issued yet")
    logging.info(f"Отправлен Root Certificate: subject={root_cert['subject']}" )
    return root_cert

@app.post("/sign_ica_cert")
def sign_ica_cert(req: ICACertRequest):
    if not keys:
        raise HTTPException(status_code=400, detail="Сначала вызовите /generate_keys и /issue_root_cert")
    if not root_cert:
        raise HTTPException(status_code=400, detail="Сертификат Root CA не выпущен")

    # Формируем data_str единообразно через construct_data_str
    data_str = construct_data_str(req.subject, req.public_key, req.timestamp)
    r = custom_hash(data_str, keys["n"])
    s = pow(r, keys["d"], keys["n"])

    signed_cert = {
        "subject": req.subject,
        "issuer": root_cert["subject"],
        "public_key": req.public_key,
        "timestamp": req.timestamp,
        "signature": {"r": r, "s": s}
    }

    filename = f"{req.subject.replace(' ', '_')}.json"
    path = os.path.join(SIGNED_ICA_DIR, filename)
    with open(path, 'w') as f:
        json.dump(signed_cert, f, indent=2)

    logging.info(
        f"Подписан сертификат для '{req.subject}': public_key={req.public_key}, "
        f"timestamp={req.timestamp}, r={r}, s={s}"
    )
    return signed_cert