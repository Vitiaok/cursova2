import socket
import threading
import json
from chain import Chain
from block import Block
from config import NetworkConfig
import time
from keys import generate_and_save_keys, sign_data
import os
from cryptography.hazmat.primitives import serialization
from Files import FileHandler

class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        generate_and_save_keys(self.node_id)
        self.host, self.port = NetworkConfig.NODES[node_id]
        self.chain = Chain()
        self.peers = NetworkConfig.get_peers(node_id)
        self.running = True
        self.file_handler = FileHandler(self)

    def load_private_key(self):
        private_key_path = f"private_key_{self.node_id}.pem"
        
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file {private_key_path} not found.")

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,  
            )
        
        return private_key
    
    def load_all_public_keys(self):
       
        public_keys = {}
    
        for node_id in self.peers:
            public_key_path = f"public_key_{node_id}.pem"
        
            if not os.path.exists(public_key_path):
                print(f"Public key file {public_key_path} not found for node {node_id}.")
                continue
        
            with open(public_key_path, "rb") as key_file:
                public_key = key_file.read()
                public_keys[node_id] = public_key
    
        return public_keys

    def handle_client(self, client_socket, addr):
        try:
            data = client_socket.recv(4096).decode('utf-8')
            message = json.loads(data)

            if message['type'] == 'validate_block':
                if message['type'] == 'validate_block':
                    block = Block(**message['block'])
                    validator_id = message['validator']  

                
                if self.chain.validate_block(block, validator_id):
                    response = {
                        'type': 'validation_success',
                        'block_hash': block.hash,
                        'validator': self.node_id  
                    }
                else:
                    response = {
                        'type': 'validation_failed',
                        'block_hash': block.hash,
                        'validator': self.node_id
                    }

                client_socket.sendall(json.dumps(response).encode('utf-8'))
                pass
            elif message['type'] == 'file_transfer':
                self.file_handler.receive_file(client_socket, message['metadata'])
                
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()

    

    def broadcast_block_for_validation(self, block):
        block_data = json.dumps({
            'type': 'validate_block',
            'block': block.dict,
            'validator': self.node_id 
        })
    
        validation_responses = []
        for peer_host, peer_port in self.peers:
            connected = False
            while not connected:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((peer_host, peer_port))
                        s.sendall(block_data.encode('utf-8'))

                        
                        response = json.loads(s.recv(4096).decode('utf-8'))
                        print(f"Validation response from {peer_host}:{peer_port}: {response}")
                        validation_responses.append(response)
                    
                    
                        if all(res.get('type') == 'validation_success' for res in validation_responses):
                            print("Block validated by all peers, adding to local chain.")
                            self.chain.add_validated_block(block)
                        else:
                            print("Block validation failed. Not adding to local chain.")
                        connected = True
                    
                except Exception as e:
                    print(f"Failed to send block to {peer_host}:{peer_port}: {e}")
                    print("Retrying in 5 seconds...")
                    time.sleep(5)

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, addr = server_socket.accept()
                print(f"Connection from {addr} has been established!")
                threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()
            except Exception as e:
                if self.running:  
                    print(f"Server error: {e}")

    def create_and_broadcast_block(self, data):
        private_key = self.load_private_key()
        new_block = self.chain.create_block(data, private_key)
    
        
        signature = sign_data(private_key, new_block.hash)
        
        new_block.signature = signature

        self.broadcast_block_for_validation(new_block)


    def user_interface(self):
        while self.running:
            command = input("\nEnter command (n: new block, f: send file, c: show chain, q: quit): ").strip().lower()

            if command == 'n':
                data = input("Enter data for the new block: ")
                self.create_and_broadcast_block(data)
            elif command == 'f':
                file_path = input("Enter path to the file to send: ")
                self.file_handler.send_file(file_path)
            elif command == 'c':
                for block in self.chain.get_chain():
                    print(json.dumps(block.dict, indent=2))
            elif command == 'q':
                self.running = False
                print("Shutting down node.")
            else:
                print("Invalid command. Try again.")


    def start(self):
       
        server_thread = threading.Thread(target=self.start_server)
        server_thread.daemon = True
        server_thread.start()
        
       
        try:
            self.user_interface()
        except KeyboardInterrupt:
            print("\nShutting down gracefully...")
        finally:
            self.running = False