import socket
import threading
import json
import base64
import os
import zlib
import hashlib
import datetime
from block import Block
from chain import Chain
from config import NetworkConfig
from keys import generate_and_save_keys, sign_data

class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        generate_and_save_keys(self.node_id)
        
        self.host, self.port = NetworkConfig.NODES[node_id]
        self.chain = Chain()
        self.peers = NetworkConfig.get_peers(node_id)
        
        self.running = True
        self.file_chunks = {}  # Кеш для тимчасового зберігання часток файлів

    def handle_client(self, client_socket, addr):
        """Обробка вхідних з'єднань з підтримкою передачі файлів"""
        try:
            # Отримання довжини повідомлення
            message_length = int.from_bytes(client_socket.recv(4), byteorder='big')
            data = client_socket.recv(message_length).decode('utf-8')
            message = json.loads(data)

            if message['type'] == 'validate_block':
                self.process_block_validation(message, client_socket)
            elif message['type'] == 'file_chunk':
                self.handle_file_chunk(message)

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()

    def process_block_validation(self, message, client_socket):
        """Валідація блоку"""
        block_data = message['block']
        block = Block(
            index=block_data['index'],
            timestamp=block_data['timestamp'],
            file_path=block_data.get('file_path'),
            file_data=block_data.get('file_data'),
            file_hash=block_data.get('file_hash'),
            total_chunks=block_data.get('total_chunks'),
            previous_hash=block_data['previous_hash'],
            nonce=block_data['nonce'],
            hash=block_data['hash'],
            signature=block_data['signature']
        )

        validator_id = message['validator']
        validation_result = self.chain.validate_block(block, validator_id)

        response = {
            'type': 'validation_success' if validation_result else 'validation_failed',
            'block_hash': block.hash,
            'validator': self.node_id
        }

        response_data = json.dumps(response).encode('utf-8')
        client_socket.sendall(len(response_data).to_bytes(4, byteorder='big'))
        client_socket.sendall(response_data)

    def handle_file_chunk(self, chunk_data):
        """Обробка вхідної частини файлу"""
        file_hash = chunk_data.get('file_hash')
        chunk_id = chunk_data.get('chunk_id')
        total_chunks = chunk_data.get('total_chunks')
        chunk = chunk_data.get('chunk')

        if file_hash not in self.file_chunks:
            self.file_chunks[file_hash] = {
                'chunks': [None] * total_chunks,
                'received_count': 0,
                'total_chunks': total_chunks
            }

        file_info = self.file_chunks[file_hash]
        file_info['chunks'][chunk_id] = chunk
        file_info['received_count'] += 1

        # Склеювання файлу при отриманні всіх часток
        if file_info['received_count'] == total_chunks:
            self.reassemble_file(file_hash)

    def reassemble_file(self, file_hash):
        """Склеювання та збереження файлу"""
        file_info = self.file_chunks[file_hash]
        
        try:
            # Декодування та склеювання
            file_bytes = b''.join([
                base64.b64decode(chunk) 
                for chunk in file_info['chunks'] 
                if chunk is not None
            ])

            # Декомпресія та перевірка хешу
            decompressed_file = zlib.decompress(file_bytes)
            calculated_hash = hashlib.sha256(decompressed_file).hexdigest()
            
            if calculated_hash != file_hash:
                raise ValueError("File integrity check failed")

            # Збереження файлу
            output_filename = self.save_reassembled_file(decompressed_file, file_hash)
            print(f"File successfully reassembled: {output_filename}")

        except Exception as e:
            print(f"Error reassembling file: {e}")
        
        # Очищення тимчасового сховища
        del self.file_chunks[file_hash]

    def save_reassembled_file(self, file_data, file_hash):
        """Збереження склеєного файлу"""
        os.makedirs('received_files', exist_ok=True)
        output_filename = os.path.join('received_files', f"{file_hash}.bin")
        
        with open(output_filename, 'wb') as f:
            f.write(file_data)
        
        return output_filename

    def create_and_broadcast_block(self, file_path):
        """Створення та розсилка блоку з файлом"""
        private_key = self.load_private_key()
        
        try:
            file_hash = Block.calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            new_block = Block(
                index=len(self.chain.blockchain),
                timestamp=datetime.datetime.now().isoformat(),
                file_path=file_path,
                previous_hash=self.chain.blockchain[-1].hash if self.chain.blockchain else "0" * 64
            )
            
            new_block.hash = self.chain.proof_of_work(new_block)
            signature = sign_data(private_key, new_block.hash)
            new_block.signature = signature

            self.broadcast_block_for_validation(new_block)
        
        except Exception as e:
            print(f"Error creating block: {e}")

    def broadcast_block_for_validation(self, block):
        """Розсилка блоку на валідацію з підтримкою великих файлів"""
        block_data = {
            'type': 'validate_block',
            'block': block.dict,
            'validator': self.node_id
        }
        
        validation_responses = []
        for peer_host, peer_port in self.peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer_host, peer_port))
                    
                    # Надсилання блоку
                    message = json.dumps(block_data).encode('utf-8')
                    s.sendall(len(message).to_bytes(4, byteorder='big'))
                    s.sendall(message)

                    # Очікування відповіді
                    response_length = int.from_bytes(s.recv(4), byteorder='big')
                    response = json.loads(s.recv(response_length).decode('utf-8'))
                    validation_responses.append(response)
            
            except Exception as e:
                print(f"Validation error with {peer_host}:{peer_port}: {e}")

        # Перевірка результатів валідації
        if all(res.get('type') == 'validation_success' for res in validation_responses):
            self.chain.add_validated_block(block)

    def start(self):
        """Запускає ноду."""
        # Запускаємо сервер в окремому потоці
        server_thread = threading.Thread(target=self.start_server)
        server_thread.daemon = True
        server_thread.start()
    
        # Запускаємо інтерфейс користувача
        try:
            self.user_interface()
        except KeyboardInterrupt:
            print("\nShutting down gracefully...")
        finally:
            self.running = False

    def start_server(self):
        """Запускає сервер для прийому з'єднань."""
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
                if self.running:  # Ігноруємо помилки при закритті сервера
                    print(f"Server error: {e}")

    def user_interface(self):
        """Інтерфейс користувача для взаємодії з нодою."""
        while self.running:
            command = input("\nEnter command (f: send file, r: retrieve file, c: show chain, q: quit): ").strip().lower()

            if command == 'f':
                file_path = input("Enter path to the file: ")
                if os.path.exists(file_path):
                    self.create_and_broadcast_block(file_path)
                else:
                    print("File does not exist!")

            elif command == 'r':
                block_hash = input("Enter block hash to retrieve file: ")
                self.retrieve_file_from_blockchain(block_hash)

            elif command == 'c':
                
                for block in self.chain.get_chain():
                    print(f"Block {block.index}: {block.hash}")
                    print(f"File path: {block.file_path}")
        
            elif command == 'q':
                self.running = False
                print("Shutting down node.")
            else:
                print("Invalid command. Try again.")

    def load_private_key(self):
        """Завантажує приватний ключ з файлу."""
        private_key_path = f"private_key_{self.node_id}.pem"
    
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file {private_key_path} not found.")

        with open(private_key_path, "rb") as key_file:
            from cryptography.hazmat.primitives import serialization
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
    
        return private_key

    def retrieve_file_from_blockchain(self, block_hash, output_directory='received_files'):
        """Отримання файлу з блокчейну за хешем блоку"""
        os.makedirs(output_directory, exist_ok=True)
    
        block = self.chain.get_block_by_hash(block_hash)
    
        if not block:
            print(f"Block with hash {block_hash} not found.")
            return None
    
        if not block.file_data:
            print(f"No file data in block {block_hash}.")
            return None
    
        try:
            return block.save_file(output_directory)
        except Exception as e:
            print(f"Error retrieving file from blockchain: {e}")
            return None