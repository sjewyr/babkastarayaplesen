import requests
import json
import os
from typing import Dict, Any, Tuple
import logging
from cert import custom_hash, ClientCertificate, IntermediateCertificate, RootCertificate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_keys_usecase() -> Dict[str, Any]:
    try:
        # Получение CLIENT_NAME из переменной окружения и удаление кавычек
        client_name = os.getenv("CLIENT_NAME")
        if not client_name:
            raise ValueError("Переменная окружения CLIENT_NAME не установлена")
        client_name = client_name.strip("'").strip('"')

        # Шаг 1. Запрос сертификата клиента и ключей
        external_endpoint = "http://ca1:8001/cert"
        logger.info("Запрос сертификата клиента и ключей с: %s, subject: %s", external_endpoint, client_name)

        # Отправка GET-запроса с параметром subject
        response = requests.get(external_endpoint, params={"subject": client_name}, timeout=10)
        response.raise_for_status()

        data = response.json()
        logger.info("Получены данные: %s", data)

        # Создание объекта клиентского сертификата
        client_cert = ClientCertificate(data, client_name)
        client_cert.validate()

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
            ica_cert_data = json.load(f)
            ica_cert = IntermediateCertificate(ica_cert_data)
            ica_cert.validate()

        with open(root_cert_path, "r") as f:
            root_cert_data = json.load(f)
            root_cert = RootCertificate(root_cert_data)
            root_cert.validate()

        logger.info("Загружены сертификаты ICA и Root")

        # Проверка цепочки сертификатов
        logger.info("Начало проверки цепочки сертификатов")

        def verify_signature(data_str: str, signature: Dict[str, int], public_key: Tuple[int, int]) -> bool:
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
        client_cert_data = client_cert.to_data_str()
        if not verify_signature(client_cert_data, client_cert.signature, ica_cert.public_key):
            raise ValueError("Подпись сертификата клиента не верна")

        # Проверка подписи сертификата ICA с помощью открытого ключа Root
        logger.info("Проверка подписи сертификата ICA с помощью открытого ключа Root")
        ica_cert_data = ica_cert.to_data_str()
        if not verify_signature(ica_cert_data, ica_cert.signature, root_cert.public_key):
            raise ValueError("Подпись сертификата ICA не верна")

        # Проверка самоподписанного сертификата Root
        logger.info("Проверка самоподписанного сертификата Root")
        root_cert_data = root_cert.to_data_str()
        if not verify_signature(root_cert_data, root_cert.signature, root_cert.public_key):
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