from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import traceback
import os

def generate_and_save_keys(node_id):
    """Генерує пару ключів (приватний та публічний) для ноди та зберігає їх у файли."""
    private_key_filename = f'private_key_{node_id}.pem'
    public_key_filename = f'public_key_{node_id}.pem'

    if os.path.exists(private_key_filename) and os.path.exists(public_key_filename):
        print(f"Keys already exist for node {node_id}. Skipping key generation.")
        return

    # Генерація приватного ключа RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Генерація публічного ключа
    public_key = private_key.public_key()

    

    # Зберігаємо приватний ключ
    with open(private_key_filename, 'wb') as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Зберігаємо публічний ключ
    with open(public_key_filename, 'wb') as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Keys generated and saved for node {node_id}")


from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature

def sign_data(private_key, data):
    """
    Підписує дані приватним ключем.
    :param private_key: Приватний ключ
    :param data: Дані для підпису
    :return: Цифровий підпис у форматі base64
    """
    signature = private_key.sign(
        data.encode('utf-8'),  # Кодуємо дані в байти
        padding.PKCS1v15(),  # Використовуємо схему PKCS#1 v1.5
        hashes.SHA256()  # Алгоритм хешування для підпису
    )
    
    
    return base64.b64encode(signature).decode('utf-8')

def validate_signature(public_key_pem, data, signature):
    """Функція для валідації підпису."""
    try:
        # Завантажуємо публічний ключ з PEM формату
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        # Декодуємо base64 підпис назад у байти
        if isinstance(signature, str):
            signature_bytes = base64.b64decode(signature)
        else:
            signature_bytes = signature
        
        
        
        # Перевіряємо підпис
        public_key.verify(
            signature_bytes,  # Підпис, який потрібно перевірити
            data.encode('utf-8'),  # Дані для перевірки
            padding.PKCS1v15(),  # Алгоритм паддінгу
            hashes.SHA256()  # Хеш-функція
        )
        return True  # Якщо підпис є дійсним

    except InvalidSignature as e:
        print("Invalid Signature Error:")
        print(f"Error details: {e}")
        traceback.print_exc()
        return False
    except Exception as e:
        # Якщо підпис не проходить перевірку
        print("Signature Validation Failed:")
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        return False
