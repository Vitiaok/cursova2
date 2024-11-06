import hashlib
import datetime as date

class Block:
    def __init__(self, index, timestamp, data, hash="0", previous_hash=None, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash

    def hashBlock(self):
        data = (str(self.index) + str(self.data) + str(self.timestamp) +
                str(self.previous_hash) + str(self.nonce)).encode('utf-8')
        return hashlib.sha256(data).hexdigest()
