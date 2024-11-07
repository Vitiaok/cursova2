import json
import datetime as date
from block import Block
import socket

HASH_TARGET = "00000"
BLOCKCHAIN_FILE = "blockchain.json"

class Chain:
    def __init__(self):
        self.blockchain = []
        self.load_chain()

    def add_block(self, data):
        """Додає новий блок або генезис-блок (як перший блок)."""
        if len(self.blockchain) == 0:
            previous_hash = "0" * 64  # Для генезис-блоку попередній хеш - це нулі
        else:
            previous_block = self.blockchain[-1]
            previous_hash = previous_block.hash

        # Створення нового блоку
        new_block = Block(len(self.blockchain), date.datetime.now().isoformat(), data, previous_hash)
        new_block.hash = self.proof_of_work(new_block)
        self.blockchain.append(new_block)
        self.save_chain()

    def get_chain(self):
        return self.blockchain

    def proof_of_work(self, block):
        """Функція для пошуку правильного хешу через майнінг (proof of work)."""
        while block.hash[:len(HASH_TARGET)] != HASH_TARGET:
            block.nonce += 1
            block.hash = block.calculate_hash()
        return block.hash

    def save_chain(self):
        """Зберігає блокчейн у файл."""
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump([block.__dict__ for block in self.blockchain], f, indent=4, sort_keys=True)
        print(f"Blockchain saved to {BLOCKCHAIN_FILE}")

    def load_chain(self):
        """Завантажує блокчейн з файлу."""
        try:
            with open(BLOCKCHAIN_FILE, 'r') as f:
                chain_data = json.load(f)
                self.blockchain = [Block(**block) for block in chain_data]
            print("Blockchain loaded successfully.")
        except (FileNotFoundError, json.JSONDecodeError):
            print("No blockchain found, starting fresh.")

    def send_blockchain(self, peer_host, peer_port):
        """Відправляє блокчейн на іншу ноду."""
        blockchain_data = json.dumps([block.__dict__ for block in self.blockchain], indent=4)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((peer_host, peer_port))
                s.sendall(blockchain_data.encode('utf-8'))
                print(f"Blockchain sent to {peer_host}:{peer_port}")
            except Exception as e:
                print(f"Failed to send blockchain: {e}")

    def receive_blockchain(self, client_socket):
        """Отримує блокчейн від іншої ноди."""
        try:
            data = client_socket.recv(4096).decode('utf-8')
            received_chain = [Block(**block) for block in json.loads(data)]
            if self.is_valid_chain(received_chain) and len(received_chain) > len(self.blockchain):
                self.blockchain = received_chain
                self.save_chain()
                print("Blockchain updated from received data.")
            else:
                print("Received blockchain is not valid or is not longer.")
        except json.JSONDecodeError:
            print("Failed to decode the received blockchain.")

    def is_valid_chain(self, chain):
        """Перевіряє, чи є ланцюг валідним."""
        for i, block in enumerate(chain[1:], 1):
            if block.previous_hash != chain[i - 1].hash or block.hash != block.calculate_hash():
                return False
        return True

    def validate_block_for_consensus(self, block):
        """Перевірка блоку на консенсус (правильність хешів, попередній хеш)."""
        if block.index == 0:  # Пропускаємо перевірку попереднього хешу для першого блоку
            print("Skipping previous hash check for Genesis block.")
        else:
            # Перевірка на правильність попереднього хешу для інших блоків
            if block.previous_hash != self.blockchain[-1].hash:
                print(f"Previous hash mismatch: expected {self.blockchain[-1].hash}, got {block.previous_hash}")
                return False

        # Перевірка на правильність хешу блоку
        if block.hash != block.calculate_hash():
            print(f"Hash mismatch: expected {block.calculate_hash()}, got {block.hash}")
            return False
        
        # Якщо блок успішно пройшов всі перевірки
        return True
