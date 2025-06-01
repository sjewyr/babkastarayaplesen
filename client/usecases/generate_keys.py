import requests
import json
import os
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import logging
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_keys_usecase() -> Dict[str, Any]:
    try:
        # Шаг 1. Запрос сертификата клиента и ключей
        external_endpoint = "http://ca1:8001/cert" # хз какой endpoint у УЦ для запроса сертификатов
        logger.info("Запрос сертификата клиента и ключей с: %s", external_endpoint)
        response = requests.get(external_endpoint, timeout=10)
        response.raise_for_status()

        data = response.json()
        logger.info("Получены данные: %s", data)

        # Проверка формата сертификата клиента
        required_keys = ["subject", "issuer", "public_key", "timestamp", "signature"]
        if not all(key in data for key in required_keys):
            raise ValueError("Полученный JSON не соответствует ожидаемому формату")

        # Сохранение сертификата клиента (предполагаю, 
        # что all_certs будет вызван раньше generate_keys, 
        # так как тут нам нужно проверку делать)
        save_dir = "certs"
        if not os.path.exists(save_dir):
            raise FileNotFoundError("Директория для сертификатов не найдена")

        client_cert_path = f"{save_dir}/client_cert.json"
        with open(client_cert_path, "w") as f:
            json.dump(data, f, indent=4)
        logger.info("Сертификат клиента сохранён в: %s", client_cert_path)

        # Шаг 2. Проверка. Загрузка сертификатов ICA и Root
        ica_cert_path = f"{save_dir}/ica_cert.json"
        root_cert_path = f"{save_dir}/root_cert.json"

        if not (os.path.exists(ica_cert_path) and os.path.exists(root_cert_path)):
            raise FileNotFoundError("Сертификат ICA или Root не найден")

        with open(ica_cert_path, "r") as f:
            ica_cert = json.load(f)
        with open(root_cert_path, "r") as f:
            root_cert = json.load(f)

        logger.info("Загружены сертификаты ICA и Root")

        # Доп. валидация
        for cert in [ica_cert, root_cert]:
            if not all(key in cert for key in required_keys):
                raise ValueError(f"Сертификат {cert.get('subject', 'unknown')} имеет неверный формат")

        # Проверка цепочки сертификатов
        logger.info("Начало проверки цепочки сертификатов")

        # Вспомогательная функция для преобразования сертификата в DER-подобный формат
        def cert_to_der_like(cert: Dict[str, Any]) -> bytes:
            cert_data = f"{cert['subject']}{cert['issuer']}{cert['public_key']}{cert['timestamp']}"
            return cert_data.encode('utf-8')

        # Вспомогательная функция для проверки ECDSA подписи
        def verify_ecdsa_signature(data: bytes, signature: str, public_key_pem: str) -> bool:
            try:
                # Загрузка открытого ключа
                public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
                
                # Декодирование подписи из base64
                signature_bytes = base64.b64decode(signature)
                
                # Вычисление хэша данных
                digest = hashes.Hash(hashes.SHA256())
                digest.update(data)
                hash_value = digest.finalize()
                
                # Проверка подписи
                public_key.verify(
                    signature_bytes,
                    hash_value,
                    ec.ECDSA(hashes.SHA256())
                )
                logger.info("Проверка подписи прошла успешно")
                return True
            except InvalidSignature:
                logger.error("Проверка подписи не удалась")
                return False
            except Exception as e:
                logger.error("Ошибка при проверке подписи: %s", str(e))
                raise

        # Проверка подписи сертификата клиента с помощью открытого ключа ICA
        logger.info("Проверка подписи сертификата клиента с помощью открытого ключа ICA")
        client_cert_data = cert_to_der_like(data)
        print(ica_cert)
        if not verify_ecdsa_signature(
            client_cert_data, 
            data['signature'], 
            ica_cert['public_key']
            ):
            raise ValueError("Подпись сертификата клиента не верна")

        # Проверка подписи сертификата ICA с помощью открытого ключа Root
        logger.info("Проверка подписи сертификата ICA с помощью открытого ключа Root")
        ica_cert_data = cert_to_der_like(ica_cert)
        if not verify_ecdsa_signature(
            ica_cert_data, 
            ica_cert['signature'], 
            root_cert['public_key']
            ):
            raise ValueError("Подпись сертификата ICA не верна")

        # Проверка самоподписанного сертификата Root (на всякий хз, хотя по идее это self-signed можно и удалить)
        logger.info("Проверка самоподписанного сертификата Root")
        root_cert_data = cert_to_der_like(root_cert)
        if not verify_ecdsa_signature(
            root_cert_data, 
            root_cert['signature'], 
            root_cert['public_key']
            ):
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
    except ConnectionAbortedError as e:
        logger.error("Непредвиденная ошибка: %s", str(e))
        return {
            "status": "error",
            "message": f"Непредвиденная ошибка: {str(e)}"
        }