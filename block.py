# block.py
import hashlib
import datetime as date

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0, hash=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()

    def calculate_hash(self):
        return hashlib.sha256(
            (str(self.index) + self.timestamp + self.data + self.previous_hash + str(self.nonce)).encode('utf-8')
        ).hexdigest()

    @property
    def dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }