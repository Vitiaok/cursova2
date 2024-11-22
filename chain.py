import json
import threading
import datetime as date
from block import Block
from keys import sign_data  
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import base64


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
        if len(self.blockchain) == 0:
            previous_hash = "0" * 64  
        else:
            previous_block = self.blockchain[-1]
            previous_hash = previous_block.hash

        
        new_block = Block(
            len(self.blockchain),
            date.datetime.now().isoformat(),
            data,
            previous_hash  
        )
    
        
        new_block.hash = self.proof_of_work(new_block)

        
        signature = sign_data(private_key, new_block.hash)

        
        new_block.signature = signature

        block_id = new_block.hash
        with self.lock:
            self.pending_blocks[block_id] = new_block
            self.validations[block_id] = set()

        return new_block

    def proof_of_work(self, block):
        while block.hash[:len(HASH_TARGET)] != HASH_TARGET:
            block.nonce += 1
            block.hash = block.calculate_hash()
        return block.hash

    def validate_block_signature(self, block, validator_id):
        try:
           
            public_key_path = f"public_key_{validator_id}.pem"
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read()
                )

            signature_bytes = base64.b64decode(block.signature)

            try:
                public_key.verify(
                    signature_bytes,
                    block.hash.encode('utf-8'),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                print(f"Invalid signature for block from validator {validator_id}")
                return False

        except Exception as e:
            print(f"Error validating signature: {e}")
            return False

    def validate_block(self, block, validator_id):
        block_id = block.hash

        if not self.is_valid_block(block):
            print("Block failed basic validation")
            return False

        if not self.validate_block_signature(block, validator_id):
            print("Block signature validation failed")
            return False

        with self.lock:
            if block_id not in self.pending_blocks:
                self.pending_blocks[block_id] = block
                self.validations[block_id] = set()

            self.validations[block_id].add(validator_id)
            print(f"Current validations for block {block_id}: {self.validations[block_id]}")
            
            if len(self.validations[block_id]) >= REQUIRED_VALIDATIONS:
                self.add_validated_block(block)
                print(f"Block {block_id} has been validated and added to the chain")
                del self.pending_blocks[block_id]
                del self.validations[block_id]
                return True

        return False

    def is_valid_block(self, block):
        if len(self.blockchain) > 0:
            if block.previous_hash != self.blockchain[-1].hash:
                print("Previous hash does not match")
                return False

        if block.hash != block.calculate_hash():
            print("Hash calculation mismatch")
            return False
        
        if block.hash[:len(HASH_TARGET)] != HASH_TARGET:
            print("Hash does not meet target difficulty")
            return False

        if block.signature is None:
            print("Block has no signature")
            return False

        return True

    def add_validated_block(self, block):
        with self.lock:
            self.blockchain.append(block)
        self.save_chain()


    def save_chain(self):
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump([block.dict for block in self.blockchain], f, indent=4, sort_keys=True)
        print(f"Blockchain saved to {BLOCKCHAIN_FILE}")

    def load_chain(self):
        try:
            with open(BLOCKCHAIN_FILE, 'r') as f:
                chain_data = json.load(f)
                self.blockchain = [Block(**block) for block in chain_data]

                for i in range(1, len(self.blockchain)):
                    if self.blockchain[i].previous_hash != self.blockchain[i - 1].hash:
                        print(f"Error: Block {i} has incorrect previous hash.")
                        break

            print("Blockchain loaded successfully.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print("No blockchain found or corrupted blockchain file, starting fresh.")

    def get_chain(self):
        
        return self.blockchain

    def remove_block_by_index(self, index):
        
        if 0 <= index < len(self.blockchain):
            del self.blockchain[index]
            self.save_chain()  
            print(f"Block #{index} has been removed.")
        else:
            print(f"Block with index {index} does not exist.")

    def get_block_by_hash(self, block_hash):
        
        for block in self.blockchain:
            if block.hash == block_hash:
                return block
        return None