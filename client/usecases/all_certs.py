import requests
import json
import os
from typing import Dict, Any
import logging
from cert import RootCertificate, IntermediateCertificate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def all_certs_usecase() -> Dict[str, Any]:
    try:
        external_endpoint = "http://ca1:8001/all_certs"
        logger.info("Получаю сертификат УЦ и корневого УЦ: %s", external_endpoint)
        response = requests.get(external_endpoint, timeout=10)
        response.raise_for_status()

        certs_data = response.json()
        logger.info("Полученные сертификаты: %s", certs_data)

        if not isinstance(certs_data, list) or len(certs_data) != 2:
            raise ValueError("Ожидалось 2 сертификата")

        # Создание объектов сертификатов
        certs = []
        for cert_data in certs_data:
            if cert_data["subject"] == "Root CA":
                cert = RootCertificate(cert_data)
            elif "Intermediate" in cert_data["subject"]:
                cert = IntermediateCertificate(cert_data)
            else:
                raise ValueError(f"Неизвестный subject: {cert_data['subject']}")
            cert.validate()
            certs.append(cert)

        save_dir = "certs"
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        saved_files = []
        for cert in certs:
            cert_type = "root_cert" if cert.subject == "Root CA" else "ica_cert"
            filename = f"{save_dir}/{cert_type}.json"
            with open(filename, "w") as f:
                json.dump({
                    "subject": cert.subject,
                    "issuer": cert.issuer,
                    "public_key": list(cert.public_key),
                    "public_key_c": list(cert.public_key_c) if cert.public_key_c else None,
                    "timestamp": cert.timestamp,
                    "signature": cert.signature
                }, f, indent=4)
            saved_files.append(filename)
            logger.info("Сертификат сохранен: %s", filename)

        return {
            "status": "success",
            "message": f"Сертификаты сохранены: {saved_files}",
            "certs": certs_data
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