import json
import hashlib
import threading
import datetime as date
from block import Block
from keys import sign_data  # Імпортуємо функцію для підпису даних

HASH_TARGET = "00000"
BLOCKCHAIN_FILE = "blockchain.json"
REQUIRED_VALIDATIONS = 1

class Chain:
    def __init__(self):
        self.blockchain = []
        self.pending_blocks = {}
        self.validations = {}
        self.lock = threading.RLock()
        self.load_chain()

    def create_block(self, data, private_key):
        """Створює новий блок, але не додає його до ланцюга."""
        # Якщо блокчейн порожній, встановлюємо попередній хеш як нульовий хеш
        if len(self.blockchain) == 0:
            previous_hash = "0" * 64  # Значення для першого блоку
        else:
            previous_block = self.blockchain[-1]
            previous_hash = previous_block.hash

        # Створення блоку
        new_block = Block(
            len(self.blockchain),
            date.datetime.now().isoformat(),
            data,
            previous_hash  # Використовуємо правильно ініціалізований попередній хеш
        )
    
        # Пошук правильного хешу через майнінг
        new_block.hash = self.proof_of_work(new_block)

        # Підписуємо блок приватним ключем
        signature = sign_data(private_key, new_block.hash)

        # Додаємо підпис до блоку
        new_block.signature = signature

        block_id = new_block.hash
        with self.lock:
            self.pending_blocks[block_id] = new_block
            self.validations[block_id] = set()

        return new_block

    def proof_of_work(self, block):
        """Функція для пошуку правильного хешу через майнінг (proof of work)."""
        while block.hash[:len(HASH_TARGET)] != HASH_TARGET:
            block.nonce += 1
            block.hash = block.calculate_hash()
        return block.hash

    def validate_block(self, block, validator_id):
        """Валідація блоку від іншої ноди."""
        block_id = block.hash

        if not self.is_valid_block(block):
            return False

        with self.lock:
            if block_id not in self.pending_blocks:
                self.pending_blocks[block_id] = block
                self.validations[block_id] = set()

            self.validations[block_id].add(validator_id)
            print(self.validations[block_id])
            if len(self.validations[block_id]) >= REQUIRED_VALIDATIONS:
                self.add_validated_block(block)
                print(1)
                del self.pending_blocks[block_id]
                del self.validations[block_id]

                return True

        return False

    def add_validated_block(self, block):
        """Додає валідований блок до ланцюга."""
        with self.lock:
            self.blockchain.append(block)
        self.save_chain()

    def is_valid_block(self, block):
        """Перевіряє валідність блоку."""
        if len(self.blockchain) > 0:
            if block.previous_hash != self.blockchain[-1].hash:
                return False

        if block.hash != block.calculate_hash():
            return False

        if block.hash[:len(HASH_TARGET)] != HASH_TARGET:
            return False

        # Перевірка підпису блоку
        if block.signature is None:
            return False

        return True

    def save_chain(self):
        """Зберігає блокчейн у файл."""
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump([block.dict for block in self.blockchain], f, indent=4, sort_keys=True)
        print(f"Blockchain saved to {BLOCKCHAIN_FILE}")

    def load_chain(self):
        """Завантажує блокчейн з файлу."""
        try:
            with open(BLOCKCHAIN_FILE, 'r') as f:
                chain_data = json.load(f)
                self.blockchain = [Block(**block) for block in chain_data]

                # Перевірка на відсутні блоки або неправильні хеші
                for i in range(1, len(self.blockchain)):
                    if self.blockchain[i].previous_hash != self.blockchain[i - 1].hash:
                        print(f"Error: Block {i} has incorrect previous hash.")
                        break

            print("Blockchain loaded successfully.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print("No blockchain found or corrupted blockchain file, starting fresh.")

    def get_chain(self):
        """Повертає поточний ланцюг блоків"""
        return self.blockchain

    def remove_block_by_index(self, index):
        """Видаляє блок за індексом з ланцюга."""
        if 0 <= index < len(self.blockchain):
            del self.blockchain[index]
            self.save_chain()  # Зберегти зміни в файлі
            print(f"Block #{index} has been removed.")
        else:
            print(f"Block with index {index} does not exist.")

    def get_block_by_hash(self, block_hash):
        """Отримує блок за хешем."""
        for block in self.blockchain:
            if block.hash == block_hash:
                return block
        return None