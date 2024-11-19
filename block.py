import hashlib
import base64

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0, hash=None, signature=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()
        
        # Ensure signature is stored as a base64 encoded string
        if signature:
            if isinstance(signature, bytes):
                # If it's bytes, encode to base64
                self.signature = base64.b64encode(signature).decode('utf-8')
            elif isinstance(signature, str):
                # If it's already a string, assume it's base64
                self.signature = signature
            else:
                self.signature = None
        else:
            self.signature = None

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
            'hash': self.hash,
            'signature': self.signature
        }