from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

import random
from sympy import nextprime


def gcd(a, b):
    # Объявление функции для вычисления наибольшего общего делителя (НОД) двух чисел a и b.
    while b:
        # Запускаем цикл, пока b не станет равно 0.
        # В Python 0 интерпретируется как False, а любое ненулевое число как True.
        a, b = b, a % b
        # В каждой итерации обновляем значения переменных a и b:
        # Новое значение a становится равным b,
        # а новое значение b становится остатком от деления старого значения a на старое значение b.
    return a
    # Как только b становится равным 0, возвращаем a, которая содержит НОД двух чисел.


def gen_right_prime_number(start, end):
    # Объявляем функцию для генерации простого числа в заданном диапазоне.
    # start и end - параметры, задающие границы диапазона.
    x = nextprime(random.randint(0xfffffff, 0xffffffffffffff))
    # Генерируем случайное число x в заданном диапазоне и находим следующее простое число, начиная с него.
    while x % 4 != 3:
        # Запускаем цикл, пока x не станет простым числом, удовлетворяющим условию x % 4 == 3.
        x = nextprime(random.randint(0xfffffff, 0xffffffffffffff))
        # Если текущее значение x не удовлетворяет условию, генерируем новое случайное число и находим следующее
        # простое число, начиная с него.
    return x
    # Возвращаем найденное простое число, удовлетворяющее условию x % 4 == 3.


def create_rand_key(m):
    # Объявление функции для создания случайного ключа.
    # m - длина ключа в битах.

    # Шаг 1: Генерация простых чисел и вычисление произведения N.
    q = gen_right_prime_number(0xfffffff, 0xffffffffffffff)
    p = gen_right_prime_number(0xffffffff, 0xffffffffffffff)
    N = p * q

    # Шаг 2: Вычисление случайного числа s в диапазоне [1, N], взаимно простого с N.
    s = N
    while gcd(N, s) > 1:
        s = random.randint(1, N)

    # Шаг 3: Генерация последовательности битов u.
    u = [(s * s) % N]  # Начальное значение u

    x = []
    for i in range(0, m):
        u.append(u[i] ** 2 % N)  # Генерация следующего элемента последовательности
        x.append(u[i + 1] & 0b1)  # Выбор младшего бита и добавление в список x

    # Шаг 4: Дополнение битов x до кратности 8 и формирование ключа.
    while len(x) % 8 > 0:
        x = [0].append(x)  # Добавление нулей в начало списка x до кратности 8

    result = []
    for i in range(0, len(x), 8):
        k = 0
        for j in range(0, 8):
            k += x[i + j] * (7 - j) ** 2  # Преобразование восьми битов в один байт
        result.append(k)  # Добавление байта в результат

    return result  # Возвращение сгенерированного ключа


def simetric_crypt(message):
    # Объявление функции для симметричного шифрования сообщения.
    # message - исходное текстовое сообщение, которое нужно зашифровать.

    # Шаг 1: Создание случайного ключа.
    rand_key = create_rand_key(32 * 8)  # Создание ключа длиной 32*8 бит
    key = bytes(rand_key)  # Преобразование ключа в байтовую строку

    # Шаг 2: Выбор используемого алгоритма шифрования (AES) и режима (CBC).
    used_algorithm = algorithms.AES(key)  # Используем AES с сгенерированным ключом
    cipher = Cipher(used_algorithm, modes.CBC(b"1234567890123456"),
                    backend=default_backend())  # Создаем объект шифрования
    encryptor = cipher.encryptor()  # Создаем объект для шифрования
    decryptor = cipher.decryptor()  # Создаем объект для дешифрования

    print("исходная текстовая строка:", message)  # Выводим исходное сообщение

    # Шаг 3: Проверка длины сообщения и дополнение до кратности 16 байтам (длине блока шифрования для AES в режиме CBC).
    if len(message) % 16 != 0:  # Проверяем, кратна ли длина сообщения 16 байтам
        message += b'\0' * (16 - len(message) % 16)  # Дополняем сообщение нулями до кратности 16 байтам

    # Шаг 4: Шифрование сообщения.
    encrypttext = encryptor.update(message)  # Шифруем данные
    encrypttext += encryptor.finalize()  # Завершаем шифрование

    print("сообщение после шифрования:", encrypttext, len(encrypttext))  # Выводим зашифрованное сообщение

    # Шаг 5: Дешифрование зашифрованного сообщения.
    decrypttext = decryptor.update(encrypttext)  # Дешифруем зашифрованные данные
    decrypttext += decryptor.finalize()  # Завершаем дешифрование

    print("сообщение после дешифрования:", decrypttext)  # Выводим дешифрованное сообщение

    return encrypttext  # Возвращаем зашифрованное сообщение


def asimetric_crypt(message):
    # Объявление функции для асимметричного шифрования сообщения.
    # message - исходное текстовое сообщение, которое нужно зашифровать.

    # Шаг 1: Генерация ключей.
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )  # Генерируем закрытый ключ заданного размера (2048 бит) и открытый ключ автоматически
    public_key = private_key.public_key()  # Получаем открытый ключ из закрытого

    # Шаг 2: Шифрование сообщения с использованием открытого ключа.
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )  # Шифруем сообщение с использованием открытого ключа и определенного метода шифрования

    # Шаг 3: Расшифрование зашифрованного сообщения с использованием закрытого ключа.
    # Объявляется переменная decrypted_message, которая будет содержать расшифрованное сообщение.
    # Функция decrypt вызывается для расшифрования зашифрованного сообщения.

    # Передается зашифрованное сообщение, которое нужно расшифровать.

    # Определяется метод заполнения OAEP (Optimal Asymmetric Encryption Padding) для расшифрования.
    # OAEP используется для обеспечения безопасности при асимметричном шифровании.

    # Определяется метод генерации маски (MGF1), который используется в OAEP.
    # В данном случае, используется хэш-алгоритм SHA256 для генерации маски.

    # Определяется хэш-алгоритм, который используется в OAEP.
    # В данном случае, используется SHA256.

    # Опциональное значение метки, которое может использоваться при шифровании OAEP.
    # В данном случае, метка не используется (устанавливается в None).

    # Закрывается вызов padding.OAEP.

    # Закрывается вызов private_key.decrypt.
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )  # Расшифровываем сообщение с использованием закрытого ключа и того же метода шифрования

    # Вывод исходного, зашифрованного и расшифрованного сообщений для проверки
    print("Исходное сообщение:", message)
    print("Зашифрованное сообщение:", ciphertext)
    print("Расшифрованное сообщение:", decrypted_message)

    return ciphertext  # Возвращаем зашифрованное сообщение


def digital_signature(message):
    # Объявление функции для создания цифровой подписи сообщения.
    # message - исходное текстовое сообщение, которое нужно подписать.

    # Шаг 1: Генерация ключей.
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )  # Генерируем закрытый ключ заданного размера (2048 бит) и открытый ключ автоматически
    public_key = private_key.public_key()  # Получаем открытый ключ из закрытого

    # Шаг 2: Подписание сообщения с использованием закрытого ключа.
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )  # Создаем цифровую подпись для сообщения с использованием закрытого ключа

    # Шаг 3: Проверка подписи с использованием открытого ключа.
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )  # Проверяем цифровую подпись с использованием открытого ключа
        print("Подпись верна")  # Если подпись верна, выводим сообщение о ее подлинности
    except:
        print("Подпись недействительна: ")  # Если подпись недействительна, выводим сообщение об ошибке

    return signature  # Возвращаем цифровую подпись


def hashing(data):
    # Объявление функции для хеширования данных.
    # data - данные, которые нужно хешировать.

    # Шаг 1: Создание объекта хеша SHA-512.
    hash_func = hashes.SHA512()

    # Шаг 2: Хеширование данных.
    hasher = hashes.Hash(hash_func, backend=default_backend())  # Создаем объект hasher для хеширования данных.
    hasher.update(data)  # Обновляем хеш с учетом переданных данных.
    digest = hasher.finalize()  # Получаем окончательное значение хеша.

    # Шаг 3: Вывод хеш-значения.
    print(digest.hex())  # Преобразуем хеш-значение в строку шестнадцатеричного формата и выводим его.

    return digest  # Возвращаем хеш-значение.

