import time
from typing import List, Tuple

# Набор малых простых для предварительной проверки
SMALL_PRIMES = [
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
]

# Глобальное зерно для псевдослучайного генератора
last_seed = int(time.time() * 1000)


def custom_random(min_val: int, max_val: int) -> int:
    global last_seed
    last_seed = (last_seed + int(time.time() * 1000)) * 25214903917
    return min_val + abs(last_seed) % (max_val - min_val + 1)


# Простой тест Ферма + проверка делимости малыми числами
def is_prime(n: int, iterations: int = 5) -> bool:
    if n < 2:
        return False
    if n in SMALL_PRIMES:
        return True
    for p in SMALL_PRIMES:
        if n % p == 0:
            return False
    for _ in range(iterations):
        a = custom_random(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True


# Генерация случайного простого числа заданной битовой длины
def generate_prime(bits: int = 64) -> int:
    while True:
        candidate = 0
        candidate |= (1 << (bits - 1)) | 1
        for i in range(1, bits - 1):
            bit = custom_random(0, 1)
            if bit == 1:
                candidate |= 1 << i
        if is_prime(candidate):
            return candidate


# Вычисление НОД
def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# Модульное обратное (расширенный алгоритм Евклида)
def modinv(a: int, m: int) -> int:
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


# Генерация ключей RSA: p, q, n, e, d
def generate_keys(bits: int = 64) -> Tuple[int, int, int, int, int]:
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return p, q, n, e, d


# Кастомный хеш-функция для строки (возвращает значение mod n)
def custom_hash(message: str, n: int) -> int:
    hash_val = 5381
    for c in message:
        hash_val = ((hash_val * 33) + ord(c)) ^ (hash_val >> 8)
        hash_val = (hash_val * 0x9E3779B9) % n
    return hash_val % n


# Функция для унификации формирования data_str
# Принимает subject, публичный ключ [e, n], и timestamp
# Возвращает строку формата "subject|e|n|timestamp"
def construct_data_str(subject: str, public_key: List[int], timestamp: int) -> str:
    return f"{subject}|{public_key[0]}|{public_key[1]}|{timestamp}"
