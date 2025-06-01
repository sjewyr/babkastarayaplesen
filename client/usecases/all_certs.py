import requests
import json
import os
from typing import Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def all_certs_usecase() -> Dict[str, Any]:
    try:
        external_endpoint = "http://ca1:8001/all_certs"

        logger.info("Получаю сертификат УЦ и корневого УЦ: %s", external_endpoint)
        response = requests.get(external_endpoint, timeout=10)

        response.raise_for_status()

        certs = response.json()
        logger.info("Полученные сертификаты: %s", certs)

        # Проверяем, что certs — это список из двух сертификатов
        if not isinstance(certs, list) or len(certs) != 2:
            raise ValueError("Ожидалось 2 сертификата")

        # Проверяем формат каждого сертификата
        required_keys_common = ["subject", "issuer", "public_key", "timestamp", "signature"]
        signature_keys = ["r", "s"]

        for cert in certs:
            # Проверка общих ключей
            if not all(key in cert for key in required_keys_common):
                raise ValueError("Сертификаты имеют неверный формат: отсутствуют обязательные ключи")

            # Проверка структуры public_key
            if not isinstance(cert["public_key"], list) or len(cert["public_key"]) != 2:
                raise ValueError("Поле public_key должно быть списком из двух чисел")
            if not all(isinstance(num, int) for num in cert["public_key"]):
                raise ValueError("Элементы public_key должны быть целыми числами")

            # Проверка структуры signature
            if not isinstance(cert["signature"], dict):
                raise ValueError("Поле signature должно быть объектом")
            if not all(key in cert["signature"] for key in signature_keys):
                raise ValueError("Поле signature должно содержать ключи 'r' и 's'")
            if not all(isinstance(cert["signature"][key], int) for key in signature_keys):
                raise ValueError("Значения 'r' и 's' в signature должны быть целыми числами")

            # Проверка public_key_c в зависимости от subject
            if cert["subject"] == "Root CA":
                if "public_key_c" in cert:
                    raise ValueError("Сертификат Root CA не должен содержать поле public_key_c")
            elif "Intermediate" in cert["subject"]:
                if not isinstance(cert.get("public_key_c"), list) or len(cert["public_key_c"]) != 2:
                    raise ValueError("Поле public_key_c в сертификате Intermediate CA должно быть списком из двух чисел")
                if not all(isinstance(num, int) for num in cert["public_key_c"]):
                    raise ValueError("Элементы public_key_c в сертификате Intermediate CA должны быть целыми числами")
            else:
                raise ValueError(f"Неизвестный subject: {cert['subject']}")

        save_dir = "certs"
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        saved_files = []
        for cert in certs:
            cert_type = "root_cert" if cert["subject"] == "Root CA" else "ica_cert"
            filename = f"{save_dir}/{cert_type}.json"
            with open(filename, "w") as f:
                json.dump(cert, f, indent=4)
            saved_files.append(filename)
            logger.info("Сертификат сохранен: %s", filename)

        return {
            "status": "success",
            "message": f"Сертификаты сохранены: {saved_files}",
            "certs": certs
        }

    except requests.exceptions.RequestException as e:
        logger.error("Не получил доступ к сертификатам: %s", str(e))
        return {
            "status": "error",
            "message": f"Не получил доступ к сертификатам: {str(e)}"
        }
    except (ValueError, KeyError) as e:
        logger.error("Валидация не прошла успешно: %s", str(e))
        return {
            "status": "error",
            "message": f"Валидация не прошла успешно: {str(e)}"
        }
    except Exception as e:
        logger.error("Неожиданная ошибка: %s", str(e))
        return {
            "status": "error",
            "message": f"Неожиданная ошибка: {str(e)}"
        }