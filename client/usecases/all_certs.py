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

        if not isinstance(certs, list) or len(certs) != 2:
            raise ValueError("Ожидалось 2 сертификата")

        # Проверяем формат каждого сертификата
        for cert in certs:
            if not all(key in cert for key in ["subject", "issuer", "public_key", "timestamp", "signature"]):
                raise ValueError("Сертификаты имеют неверный формат")

        save_dir = "certs"
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        saved_files = []
        for i, cert in enumerate(certs):
            cert_type = "ica_cert" if cert["subject"] == "Root CA" else "root_cert"
            filename = f"{save_dir}/{cert_type}.json"
            with open(filename, "w") as f:
                json.dump(cert, f, indent=4)
            saved_files.append(filename)
            logger.info("Сертификаты сохранены: %s", filename)

        return {
            "status": "success",
            "message": f"Сертификаты сохранены {saved_files}",
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