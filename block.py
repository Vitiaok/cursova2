import hashlib
import datetime as date

class Block:
    def __init__(self, index, timestamp, data, previous_hash="0", nonce=0, hash=""):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash or self.calculate_hash()  # Calculate if not provided

    def calculate_hash(self):
        data = (str(self.index) + str(self.data) + str(self.timestamp) +
                str(self.previous_hash) + str(self.nonce)).encode('utf-8')
        return hashlib.sha256(data).hexdigest()
