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
        required_keys = [
            "subject",
            "issuer",
            "public_key",
            "public_key_c",
            "timestamp",
            "signature",
        ]
        for cert in certs:
            if not all(key in cert for key in required_keys):
                raise ValueError(
                    "Сертификаты имеют неверный формат: отсутствуют обязательные ключи"
                )

            # Дополнительная валидация структуры public_key и public_key_c
            for key in ["public_key", "public_key_c"]:
                if not isinstance(cert[key], list) or len(cert[key]) != 2:
                    raise ValueError(f"Поле {key} должно быть списком из двух чисел")
                if not all(isinstance(num, int) for num in cert[key]):
                    raise ValueError(f"Элементы {key} должны быть целыми числами")

            # Валидация структуры signature
            if not isinstance(cert["signature"], dict):
                raise ValueError("Поле signature должно быть объектом")
            if not all(key in cert["signature"] for key in ["r", "s"]):
                raise ValueError("Поле signature должно содержать ключи 'r' и 's'")
            if not all(isinstance(cert["signature"][key], int) for key in ["r", "s"]):
                raise ValueError(
                    "Значения 'r' и 's' в signature должны быть целыми числами"
                )

        save_dir = "certs"
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        saved_files = []
        for i, cert in enumerate(certs):  # Исправлено: добавлен индекс i
            cert_type = "ica_cert" if cert["subject"] == "Root CA" else "root_cert"
            filename = f"{save_dir}/{cert_type}.json"
            with open(filename, "w") as f:
                json.dump(cert, f, indent=4)
            saved_files.append(filename)
            logger.info("Сертификат сохранен: %s", filename)

        return {
            "status": "success",
            "message": f"Сертификаты сохранены: {saved_files}",
            "certs": certs,
        }

    except requests.exceptions.RequestException as e:
        logger.error("Не получил доступ к сертификатам: %s", str(e))
        return {
            "status": "error",
            "message": f"Не получил доступ к сертификатам: {str(e)}",
        }
    except (ValueError, KeyError) as e:
        logger.error("Валидация не прошла успешно: %s", str(e))
        return {"status": "error", "message": f"Валидация не прошла успешно: {str(e)}"}
    except Exception as e:
        logger.error("Неожиданная ошибка: %s", str(e))
        return {"status": "error", "message": f"Неожиданная ошибка: {str(e)}"}
