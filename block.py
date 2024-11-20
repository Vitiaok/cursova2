import hashlib
import base64
import os
import zlib
import datetime

class Block:
    def __init__(self, index, timestamp, file_path=None, file_data=None, 
                 previous_hash=None, nonce=0, hash=None, signature=None, 
                 file_hash=None, total_chunks=None):
        self.index = index
        self.timestamp = timestamp
        self.file_path = file_path
        self.file_hash = file_hash
        self.total_chunks = total_chunks
        
        # Оптимізована робота з файлами
        if file_path and not file_data:
            self.file_data = self.compress_and_encode_file(file_path)
            self.file_hash = self.calculate_file_hash(file_path)
        elif file_data:
            self.file_data = file_data
        else:
            self.file_data = None
        
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()
        
        # Підписування
        self.signature = self._process_signature(signature)

    @staticmethod
    def compress_and_encode_file(file_path):
        """Стиснення та кодування файлу"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as file:
            file_data = file.read()
            compressed_data = zlib.compress(file_data)
            return base64.b64encode(compressed_data).decode('utf-8')

    @staticmethod
    def calculate_file_hash(file_path):
        """Обчислення хешу файлу"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _process_signature(self, signature):
        """Обробка підпису"""
        if signature:
            return (base64.b64encode(signature).decode('utf-8') 
                    if isinstance(signature, bytes) 
                    else signature)
        return None

    def calculate_hash(self):
        """Обчислення хешу блоку з оптимізацією"""
        hash_components = [
            str(self.index),
            str(self.timestamp),
            str(self.file_hash or ''),
            str(self.previous_hash or ''),
            str(self.nonce)
        ]
        hash_input = ''.join(hash_components)
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

    def save_file(self, output_directory):
        """Збереження файлу з блоку"""
        if not self.file_data:
            raise ValueError("No file data in this block")
        
        os.makedirs(output_directory, exist_ok=True)
        
        # Декодування та декомпресія
        compressed_data = base64.b64decode(self.file_data)
        decompressed_data = zlib.decompress(compressed_data)
        
        # Визначення розширення
        file_extension = (os.path.splitext(self.file_path)[1] 
                          if self.file_path else '.bin')
        
        output_filename = os.path.join(
            output_directory, 
            f"{self.file_hash}{file_extension}"
        )
        
        with open(output_filename, 'wb') as file:
            file.write(decompressed_data)
        
        return output_filename

    @property
    def dict(self):
        """Представлення блоку як словника"""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'file_path': self.file_path,
            'file_data': self.file_data,
            'file_hash': self.file_hash,
            'total_chunks': self.total_chunks,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash,
            'signature': self.signature
        }