import requests
import json
import os
from typing import Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def custom_hash(data_str: str, n: int) -> int:
    hash_val = 5381
    for c in data_str:
        hash_val = ((hash_val * 33) + ord(c)) ^ (hash_val >> 8)
        hash_val = (hash_val * 0x9e3779b9) % n
    return hash_val % n

def generate_keys_usecase() -> Dict[str, Any]:
    try:
        # Шаг 1. Запрос сертификата клиента и ключей
        external_endpoint = "http://ca1:8001/cert"
        logger.info("Запрос сертификата клиента и ключей с: %s", external_endpoint)
        response = requests.get(external_endpoint, timeout=10)
        response.raise_for_status()

        data = response.json()
        logger.info("Получены данные: %s", data)

        # Проверка формата полученного JSON
        required_keys = ["public_key", "private_key", "certificate"]
        certificate_keys = ["subject", "issuer", "public_key", "public_key_c", "timestamp", "signature"]
        signature_keys = ["r", "s"]
        if not all(key in data for key in required_keys):
            raise ValueError("Полученный JSON не содержит обязательных ключей")
        if not all(key in data["certificate"] for key in certificate_keys):
            raise ValueError("Сертификат клиента имеет неверный формат")
        if not all(key in data["certificate"]["signature"] for key in signature_keys):
            raise ValueError("Поле signature в сертификате клиента имеет неверный формат")

        # Проверка структуры public_key и public_key_c
        for key in ["public_key", "public_key_c", "certificate.public_key"]:
            key_parts = data["certificate"]["public_key"] if key == "certificate.public_key" else data[key]
            if not (isinstance(key_parts, list) and len(key_parts) == 2 and all(isinstance(x, int) for x in key_parts)):
                raise ValueError(f"Поле {key} должно быть списком из двух целых чисел")
        if not isinstance(data["private_key"], int):
            raise ValueError("Поле private_key должно быть целым числом")
        if not all(isinstance(data["certificate"]["signature"][k], int) for k in signature_keys):
            raise ValueError("Поля r и s в signature должны быть целыми числами")

        # Сохранение сертификата клиента
        save_dir = "certs"
        if not os.path.exists(save_dir):
            raise FileNotFoundError("Директория для сертификатов не найдена")

        client_cert_path = f"{save_dir}/client_cert.json"
        with open(client_cert_path, "w") as f:
            json.dump(data, f, indent=4)
        logger.info("Сертификат клиента сохранён в: %s", client_cert_path)

        # Шаг 2. Загрузка сертификатов ICA и Root
        ica_cert_path = f"{save_dir}/ica_cert.json"
        root_cert_path = f"{save_dir}/root_cert.json"

        if not (os.path.exists(ica_cert_path) and os.path.exists(root_cert_path)):
            raise FileNotFoundError("Сертификат ICA или Root не найден")

        with open(ica_cert_path, "r") as f:
            ica_cert = json.load(f)
        with open(root_cert_path, "r") as f:
            root_cert = json.load(f)

        logger.info("Загружены сертификаты ICA и Root")

        # Проверка формата сертификатов ICA и Root
        for cert in [ica_cert, root_cert]:
            if not all(key in cert for key in ["subject", "issuer", "public_key", "timestamp", "signature"]):
                raise ValueError(f"Сертификат {cert.get('subject', 'unknown')} имеет неверный формат")
            if not (isinstance(cert["public_key"], list) and len(cert["public_key"]) == 2 and all(isinstance(x, int) for x in cert["public_key"])):
                raise ValueError(f"Поле public_key в сертификате {cert.get('subject', 'unknown')} должно быть списком из двух целых чисел")
            if not all(isinstance(cert["signature"][k], int) for k in signature_keys):
                raise ValueError(f"Поля r и s в signature сертификата {cert.get('subject', 'unknown')} должны быть целыми числами")

        # Проверка цепочки сертификатов
        logger.info("Начало проверки цепочки сертификатов")

        # Вспомогательная функция для создания строки данных для подписи
        def cert_to_data_str(cert: Dict[str, Any]) -> str:
            return f"{cert['subject']}|{cert['public_key'][0]}|{cert['public_key'][1]}|{cert['timestamp']}"

        # Вспомогательная функция для проверки подписи
        def verify_signature(data_str: str, signature: Dict[str, int], public_key: list) -> bool:
            try:
                e, n = public_key
                s = signature["s"]
                r_expected = custom_hash(data_str, n)
                r_from_signature = pow(s, e, n)
                if r_expected == r_from_signature:
                    logger.info("Проверка подписи прошла успешно")
                    return True
                else:
                    logger.error("Проверка подписи не удалась: r_expected != r_from_signature")
                    return False
            except Exception as e:
                logger.error("Ошибка при проверке подписи: %s", str(e))
                raise

        # Проверка подписи сертификата клиента с помощью открытого ключа ICA
        logger.info("Проверка подписи сертификата клиента с помощью открытого ключа ICA")
        client_cert_data = cert_to_data_str(data["certificate"])
        if not verify_signature(client_cert_data, data["certificate"]["signature"], ica_cert["public_key"]):
            raise ValueError("Подпись сертификата клиента не верна")

        # Проверка подписи сертификата ICA с помощью открытого ключа Root
        logger.info("Проверка подписи сертификата ICA с помощью открытого ключа Root")
        ica_cert_data = cert_to_data_str(ica_cert)
        if not verify_signature(ica_cert_data, ica_cert["signature"], root_cert["public_key"]):
            raise ValueError("Подпись сертификата ICA не верна")

        # Проверка самоподписанного сертификата Root
        logger.info("Проверка самоподписанного сертификата Root")
        root_cert_data = cert_to_data_str(root_cert)
        if not verify_signature(root_cert_data, root_cert["signature"], root_cert["public_key"]):
            raise ValueError("Подпись сертификата Root не верна")

        logger.info("Проверка цепочки сертификатов успешно завершена")

        return {
            "status": "success",
            "message": f"Сертификат сохранён в {client_cert_path} и проверка цепочки прошла успешно",
            "data": data
        }

    except requests.exceptions.RequestException as e:
        logger.error("Не удалось получить данные: %s", str(e))
        return {
            "status": "error",
            "message": f"Не удалось получить данные: {str(e)}"
        }
    except (ValueError, KeyError) as e:
        logger.error("Ошибка валидации: %s", str(e))
        return {
            "status": "error",
            "message": f"Ошибка валидации: {str(e)}"
        }
    except FileNotFoundError as e:
        logger.error("Ошибка с файлами: %s", str(e))
        return {
            "status": "error",
            "message": f"Ошибка с файлами: {str(e)}"
        }
    except Exception as e:
        logger.error("Непредвиденная ошибка: %s", str(e))
        return {
            "status": "error",
            "message": f"Непредвиденная ошибка: {str(e)}"
        }