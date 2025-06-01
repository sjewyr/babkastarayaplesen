from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import time
import os
import json
import logging
import time
import requests
from utils import generate_keys, custom_hash, construct_data_str

FIRST_SERVER_URL = "http://root_ca:8000"
CERT_PATH = "signed_ica_certs"
local_root_cert = None

app = FastAPI()

# Настройка логирования
LOG_PATH = os.path.join(os.getcwd(), "data", "logs")
os.makedirs(LOG_PATH, exist_ok=True)
log_file = os.path.join(LOG_PATH, "service.log")

# Очистка лога перед запуском
with open(log_file, "w"):
    pass

# Настройка логгера
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S,%f",
)

# В памяти
keys: dict[str, int] = {}
root_cert: dict = {}

# Каталоги
CERT_STORE = os.path.join(os.getcwd(), "cert_store")
SIGNED_ICA_DIR = os.path.join(CERT_STORE, "signed_ica_certs")
os.makedirs(SIGNED_ICA_DIR, exist_ok=True)


# Модель запроса на подпись
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


@app.get("/get_root_cert")
def get_root_cert():
    global local_root_cert
    try:
        response = requests.get(f"{FIRST_SERVER_URL}/send_root_cert")
        if response.status_code == 200:
            root_cert = response.json()
            filename = "root.json"
            path = os.path.join("signed_ica_certs", filename)
            with open(path, "w") as f:
                json.dump(root_cert, f, indent=2)
            logging.info(f"Получен Root Certificate: subject={root_cert['subject']}")
            return root_cert
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail="Ошибка при получении корневого сертификата",
            )
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка подключения к первому серверу: {e}")
        raise HTTPException(
            status_code=503,
            detail="Не удалось подключиться к серверу с корневым сертификатом",
        )


@app.post("/request_ica_cert")
def request_ica_cert():
    try:
        if not keys:
            raise HTTPException(
                status_code=400, detail="Сначала вызовите /generate_keys"
            )

        public_key = [keys["e"], keys["n"]]
        subject = "Intermediate CA2 "

        timestamp = int(time.time())
        ica_request = {
            "subject": subject,
            "public_key": public_key,
            "timestamp": timestamp,
        }

        response = requests.post("http://root_ca:8000/sign_ica_cert", json=ica_request)
        response.raise_for_status()

        signed_cert = response.json()

        filename = "ica.json"
        path = os.path.join("signed_ica_certs", filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(signed_cert, f, indent=2)

        logging.info(
            f"Получен и сохранён подписанный сертификат для '{subject}': {path}"
        )
        return signed_cert

    except requests.exceptions.HTTPError as e:
        status_code = response.status_code
        logging.error(f"Ошибка {status_code} при запросе к root_ca: {e}")
        raise HTTPException(status_code=status_code, detail="Ошибка на стороне root_ca")

    except requests.exceptions.RequestException as e:
        logging.error(f"Сетевая ошибка при подключении к root_ca: {e}")
        raise HTTPException(status_code=503, detail="Невозможно подключиться к root_ca")

    except Exception as e:
        logging.error(f"Произошла ошибка: {e}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера")


@app.get("/all_certs")
def all_certs():
    cert_files = [f for f in os.listdir(CERT_PATH) if f.endswith(".json")]

    if not cert_files:
        raise HTTPException(status_code=404, detail="В папке нет JSON-файлов")

    cert_list = []
    for filename in cert_files:
        file_path = os.path.join(CERT_PATH, filename)
        try:
            with open(file_path, "r") as f:
                cert_data = json.load(f)
                cert_list.append(cert_data)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=500, detail=f"Ошибка чтения файла {filename}"
            )

    return cert_list


@app.get("/cert")
def client_cert(subject: str):
    client_keys: dict[str, int] = {}
    p, q, n, e, d = generate_keys()
    client_keys.update({"p": p, "q": q, "n": n, "e": e, "d": d})
    logging.info(
        f"Сгенерированы ключи RSA для клиента: p={p}, q={q}, n={n}, e={e}, d={d}"
    )

    try:
        with open(f"{CERT_PATH}/ica.json", "r") as f:
            cert_data = json.load(f)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Ошибка чтения JSON из файла")

    timestamp = int(time.time())
    public_key_c = [client_keys["e"], client_keys["n"]]

    data_str = construct_data_str(subject, public_key_c, timestamp)
    r = custom_hash(data_str, keys["n"])
    s = pow(r, keys["d"], keys["n"])
    signature = {"r": r, "s": s}
    public_key = [keys["e"], keys["n"]]

    signed_cert = {
        "public_key": public_key_c,
        "private_key": client_keys["d"],
        "certificate": {
            "subject": subject,
            "issuer": "Intermediate CA2",
            "public_key": public_key,
            "public_key_c": public_key_c,
            "timestamp": timestamp,
            "signature": signature,
        },
    }

    return signed_cert
