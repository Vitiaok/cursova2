import json
import os
from block import Block
import datetime as date
import socket

HASH_TARGET = "00000"
BLOCKCHAIN_FILE ="blockchain.json"

class Chain:
    def __init__(self):
        self.blockchain = []
        self.load_chain()  # Загружаємо блокчейн з файлу, якщо він існує

    def addBlock(self, data):
        if len(self.blockchain) == 0:
            previous_hash = "0" * 64
            newBlock = Block(len(self.blockchain), date.datetime.now().isoformat(), data, previous_hash=previous_hash)
        else:
            previousBlock = self.blockchain[-1]
            newBlock = Block(len(self.blockchain), date.datetime.now().isoformat(), data, previous_hash=previousBlock.hash)

        newBlock.hash = self.proofOfWork(newBlock)
        self.blockchain.append(newBlock)
        self.save_chain()  # Зберігаємо блокчейн після додавання блоку

    def getChain(self):
        return self.blockchain

    def proofOfWork(self, block):
        while block.hash[:len(HASH_TARGET)] != HASH_TARGET:
            block.nonce += 1
            block.hash = block.hashBlock()
        return block.hash

    def save_chain(self):
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump(
                [{
                    'index': block.index,
                    'timestamp': block.timestamp,
                    'data': block.data,
                    'previous_hash': block.previous_hash,  # Змінено на previous_hash
                    'nonce': block.nonce,
                    'hash': block.hash
                } for block in self.blockchain],
                f,
                indent=4,
                sort_keys=True
            )
        print(f"Blockchain saved to {BLOCKCHAIN_FILE}")

    def load_chain(self):
        try:
            with open(BLOCKCHAIN_FILE, 'r') as f:
                self.blockchain = [Block(**{**block, 'previous_hash': block.pop('previous_hash')}) for block in json.load(f)]
            print("Blockchain loaded successfully.")
        except (FileNotFoundError, json.JSONDecodeError):
            self.blockchain = []
            print("No blockchain found, starting fresh.")

    def send_blockchain(self, peer_host, peer_port):
        # Форматування даних блокчейну для передачі
        blockchain_data = [block.__dict__ for block in self.blockchain]
        json_data = json.dumps(blockchain_data, indent=4)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((peer_host, peer_port))
                s.sendall(json_data.encode('utf-8'))
                print(f"Blockchain sent to {peer_host}:{peer_port}")
            except Exception as e:
                print(f"Failed to send blockchain: {e}")