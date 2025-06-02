import logging
from typing import Dict, Any, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def custom_hash(data_str: str, n: int) -> int:
    hash_val = 5381
    for c in data_str:
        hash_val = ((hash_val * 33) + ord(c)) ^ (hash_val >> 8)
        hash_val = (hash_val * 0x9E3779B9) % n
    return hash_val % n


class Certificate:
    def __init__(self, data: Dict[str, Any]):
        self.subject = data.get("subject", "")
        self.issuer = data.get("issuer", "")
        self.public_key: Tuple[int, int] = tuple(data.get("public_key", []))
        self.public_key_c: Tuple[int, int] | None = (
            tuple(data.get("public_key_c", [])) if data.get("public_key_c") else None
        )
        self.timestamp = data.get("timestamp", 0)
        self.signature: Dict[str, int] = data.get("signature", {})

    def validate(self) -> None:
        if not self.subject or not isinstance(self.subject, str):
            raise ValueError(
                f"Поле subject должно быть непустой строкой: {self.subject}"
            )
        if not self.issuer or not isinstance(self.issuer, str):
            raise ValueError(f"Поле issuer должно быть непустой строкой: {self.issuer}")
        if not (
            isinstance(self.public_key, tuple)
            and len(self.public_key) == 2
            and all(isinstance(x, int) for x in self.public_key)
        ):
            raise ValueError(
                f"Поле public_key должно быть списком из двух целых чисел: {self.public_key}"
            )
        if not (isinstance(self.timestamp, int) and self.timestamp > 0):
            raise ValueError(
                f"Поле timestamp должно быть положительным целым числом: {self.timestamp}"
            )
        if (
            not isinstance(self.signature, dict)
            or not all(k in self.signature for k in ["r", "s"])
            or not all(isinstance(self.signature[k], int) for k in ["r", "s"])
        ):
            raise ValueError(
                f"Поле signature должно быть объектом с целочисленными r и s: {self.signature}"
            )

    def to_data_str(self) -> str:
        return (
            f"{self.subject}|{self.public_key[0]}|{self.public_key[1]}|{self.timestamp}"
        )

    def client_data_str(self):
        return f"{self.subject}|{self.public_key_c[0]}|{self.public_key_c[1]}|{self.timestamp}"


class RootCertificate(Certificate):
    def validate(self) -> None:
        super().validate()
        if self.public_key_c is not None:
            raise ValueError("Сертификат Root CA не должен содержать поле public_key_c")
        if self.subject != "Root CA":
            raise ValueError(f"Ожидалось subject='Root CA', получено: {self.subject}")


class IntermediateCertificate(Certificate):
    def validate(self) -> None:
        super().validate()
        if (
            not isinstance(self.public_key_c, tuple)
            or len(self.public_key_c) != 2
            or not all(isinstance(x, int) for x in self.public_key_c)
        ):
            raise ValueError(
                f"Поле public_key_c в сертификате Intermediate CA должно быть списком из двух целых чисел: {self.public_key_c}"
            )
        if "Intermediate" not in self.subject:
            raise ValueError(
                f"Ожидалось 'Intermediate' в subject, получено: {self.subject}"
            )


class ClientCertificate(Certificate):
    def __init__(self, data: Dict[str, Any], expected_subject: str):
        super().__init__(data["certificate"])
        self.public_key_top = tuple(data.get("public_key", []))
        self.private_key = data.get("private_key", 0)
        self.expected_subject = expected_subject

    def validate(self) -> None:
        super().validate()
        if (
            not isinstance(self.public_key_top, tuple)
            or len(self.public_key_top) != 2
            or not all(isinstance(x, int) for x in self.public_key_top)
        ):
            raise ValueError(
                f"Поле public_key (в корне) должно быть списком из двух целых чисел: {self.public_key_top}"
            )
        if not isinstance(self.private_key, int):
            raise ValueError(
                f"Поле private_key должно быть целым числом: {self.private_key}"
            )
        if (
            not isinstance(self.public_key_c, tuple)
            or len(self.public_key_c) != 2
            or not all(isinstance(x, int) for x in self.public_key_c)
        ):
            raise ValueError(
                f"Поле public_key_c в сертификате клиента должно быть списком из двух целых чисел: {self.public_key_c}"
            )
        if self.subject != self.expected_subject:
            raise ValueError(
                f"Ожидалось subject={self.expected_subject}, получено: {self.subject}"
            )
