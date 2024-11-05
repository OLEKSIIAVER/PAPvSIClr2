import os
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.backends import default_backend


# Функція для генерації ключа та IV
def generate_key_and_iv(password: bytes, salt: bytes):
    # Ініціалізація KDF (Key Derivation Function) з використанням алгоритму PBKDF2 та SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 байти = 256 біт для AES-256
        salt=salt,
        iterations=100000, # Кількість ітерацій для підвищення безпеки
        backend=default_backend()
    )
    key = kdf.derive(password) # Виведення ключа на основі пароля
    iv = os.urandom(16)  # 16 байт = 128 біт для AES
    return key, iv

# Функція для шифрування файлу
def encrypt_file(input_file: str, output_file: str, password: bytes):
    salt = os.urandom(16) # Генерація випадкової "солі" довжиною 16 байт
    key, iv = generate_key_and_iv(password, salt) # Генерація ключа та IV

    with open(input_file, 'rb') as f:
        data = f.read()  # Читання вмісту файлу для шифрування

    # Додавання доповнення (padding) до даних
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Створення об'єкта шифрування з алгоритмом AES у режимі CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Генерація MAC (Message Authentication Code) для автентифікації
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    mac = h.finalize()

    # Збереження солі, IV, MAC та зашифрованих даних у вихідний файл
    with open(output_file, 'wb') as f:
        f.write(salt + iv + mac + encrypted_data)

# Функція для дешифрування файлу
def decrypt_file(input_file: str, output_file: str, password: bytes):
    try:
        # Читання вмісту файлу для дешифрування
        with open(input_file, 'rb') as f:
            content = f.read()
            if len(content) < 64:  # Перевірка на достатню довжину
                raise ValueError("Вхідний файл закороткий, щоб містити дійсні дані")

            print("Довжина:", len(content))  # Додано для відлагодження
            salt = content[:16]
            iv = content[16:32]
            mac = content[32:64]
            encrypted_data = content[64:]

            # Виділення "солі", IV, MAC та зашифрованих даних із файлу
            print("Salt:", salt)
            print("IV:", iv)
            print("MAC:", mac)
            print("Довжина зашифрованих даних:", len(encrypted_data))

        # Відтворення ключа на основі пароля та "солі"
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        ).derive(password)

        # Перевірка MAC для автентифікації даних
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        h.verify(mac)

        # Створення об'єкта дешифрування
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Видалення доповнення
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Запис розшифрованих даних у вихідний файл
        with open(output_file, 'wb') as f:
            f.write(data)
            print(f"Розшифровані дані записуються в {output_file}, розмір: {len(data)} байт")  # Додано для відлагодження

    except Exception as e:
        print(f"Під час дешифрування сталася помилка: {e}")
        messagebox.showerror("Помилка", f"Розшифрування. Невдача: {e}")


# Функція для генерації пари ключів RSA
def generate_rsa_keys():
    # Генерація приватного ключа RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key() # Отримання публічного ключа

    # Серіалізація приватного ключа в PEM формат
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Серіалізація публічного ключа в PEM формат
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public

# Функція для шифрування даних з використанням RSA
def rsa_encrypt(data: bytes, public_key: bytes):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_data = public_key.encrypt(
        data,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

# Функція для підписування даних
def sign_data(data: bytes, private_key: bytes):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    signature = private_key.sign(
        data,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Функція для перевірки підпису
def verify_signature(data: bytes, signature: bytes, public_key: bytes):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    public_key.verify(
        signature,
        data,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Функція для вибору файлу через графічний інтерфейс
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        input_file_entry.delete(0, 'end')
        input_file_entry.insert(0, file_path)

# Функція для шифрування файлу через інтерфейс
def encrypt_action():
    password = password_entry.get().encode()
    input_file = input_file_entry.get()
    if not input_file or not password:
        messagebox.showerror("Помилка", "Введіть пароль та оберіть файл")
        return
    encrypted_file = "encrypted.bin"
    encrypt_file(input_file, encrypted_file, password)
    messagebox.showinfo("Успішно", "Файл успішно зашифровано")

# Функція для дешифрування файлу через інтерфейс
def decrypt_action():
    password = password_entry.get().encode()
    input_file = "encrypted.bin"
    decrypted_file = "decrypted.txt"
    if not password:
        messagebox.showerror("Помилка", "Введіть пароль")
        return
    decrypt_file(input_file, decrypted_file, password)
    messagebox.showinfo("Успішно", "Файл успішно розшифровано")

# Налаштування графічного інтерфейсу
root = Tk()
root.title("AES Encryption/Decryption")

# Поле для введення пароля
Label(root, text="Пароль:").grid(row=0, column=0)
password_entry = Entry(root, show='*')
password_entry.grid(row=0, column=1)

# Поле для введення шляху до файлу
Label(root, text="Вхідний файл:").grid(row=1, column=0)
input_file_entry = Entry(root)
input_file_entry.grid(row=1, column=1)
Button(root, text="Обрати файл", command=select_file).grid(row=1, column=2)

Button(root, text="Зашифрувати", command=encrypt_action).grid(row=2, column=0, columnspan=3) # Кнопка для шифрування
Button(root, text="Розшифрувати", command=decrypt_action).grid(row=3, column=0, columnspan=3) # Кнопка для дешифрування

root.mainloop() # Запуск програми
