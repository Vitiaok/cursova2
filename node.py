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
import struct
HASH_TARGET = "00000"
MULTICAST_GROUP = '224.0.0.1'  # Стандартна адреса мультикаст-групи
MULTICAST_PORT = 5007          # Порт для мультикасту
BUFFER_SIZE = 1024

class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        generate_and_save_keys(self.node_id)
        
        # Get discovery port and host
        self.discovery_host, self.discovery_port = NetworkConfig.get_node_info(node_id)
        
        # Calculate file transfer port
        self.file_transfer_port = NetworkConfig._discovery.get_file_transfer_port(self.discovery_port)
        
        # Use file transfer port for main node operations
        self.host = self.discovery_host
        self.port = self.file_transfer_port
        
        self.chain = Chain()
        self.peers = self._get_file_transfer_peers()
        self.running = True
        self.file_handler = FileHandler(self)
        self.force_sync_required = False

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
                block = Block(**message['block'])
                validator_id = message['validator']
                
                # Check if block already exists in chain
                if any(existing.hash == block.hash for existing in self.chain.blockchain):
                    print(f"Block {block.hash} already exists in chain, skipping validation")
                    response = {
                        'type': 'validation_failed',
                        'block_hash': block.hash,
                        'validator': self.node_id,
                        'reason': 'duplicate_block'
                    }
                else:
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
                            'validator': self.node_id,
                            'reason': 'validation_failed'
                        }
                
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
            elif message['type'] == 'file_transfer':
                self.file_handler.receive_file(client_socket, message['metadata'])
                
            elif message['type'] == 'get_chain':
                response = {
                    'type': 'chain_data',
                    'chain': self.chain.get_chain_snapshot()
                }
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
            elif message['type'] == 'get_block':
                block_index = message['block_index']
                if 0 <= block_index < len(self.chain.blockchain):
                    response = {
                        'type': 'block_data',
                        'block': self.chain.blockchain[block_index].dict
                    }
                else:
                    response = {
                        'type': 'block_data',
                        'block': None
                    }
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
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
        validated = False  # Flag to track if block was already validated and added
        
        for peer_host, peer_port in self.peers:
            if validated:  # Skip remaining peers if block was already validated
                break
                
            connected = False
            retries = 3  # Limit retries to avoid infinite loop
            
            while not connected and retries > 0:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((peer_host, peer_port))
                        s.sendall(block_data.encode('utf-8'))
                        
                        response = json.loads(s.recv(4096).decode('utf-8'))
                        print(f"Validation response from {peer_host}:{peer_port}: {response}")
                        validation_responses.append(response)
                        
                        # Check if we have enough validations
                        successful_validations = sum(1 for res in validation_responses 
                                                if res.get('type') == 'validation_success')
                        
                        # If we have majority of validations (>50% of peers)
                        if not validated and successful_validations > len(self.peers) // 2:
                            print("Block received majority validation, adding to local chain.")
                            self.chain.add_validated_block(block)
                            validated = True  # Mark as validated to avoid duplicate additions
                        
                        connected = True
                    
                except Exception as e:
                    print(f"Failed to send block to {peer_host}:{peer_port}: {e}")
                    print(f"Retries left: {retries}")
                    retries -= 1
                    if retries > 0:
                        time.sleep(5)

        if not validated:
            print("Block validation failed: Could not get majority validation from peers.")

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of the address
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"Connection from {addr} has been established!")
                threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()
            except Exception as e:
                if self.running:  # Avoid printing errors when shutting down
                    print(f"Server error: {e}")

    def create_and_broadcast_block(self, data):
        private_key = self.load_private_key()
        new_block = self.chain.create_block(data, private_key)
    
        
        signature = sign_data(private_key, new_block.hash)
        
        new_block.signature = signature

        self.broadcast_block_for_validation(new_block)


    def user_interface(self):
        while self.running:
            command = input("\nEnter command (f: send file, c: show chain, q: quit): ").strip().lower()

            if command == 'f':
                file_path = input("Enter path to the file to send: ")
                self.file_handler.send_file(file_path)
            elif command == 'c':
                for block in self.chain.get_chain():
                    print(json.dumps(block.dict, indent=2))
            elif command == 'q':
                print("Shutting down node...")
                self.running = False

                # Закриття сервера (звільнення порту)
                if hasattr(self, 'server_socket') and self.server_socket:
                    try:
                        self.server_socket.close()
                        print("Server socket closed successfully.")
                    except Exception as e:
                        print(f"Error closing server socket: {e}")

                print("Node shutdown complete.")
            else:
                print("Invalid command. Try again.")



    def start(self):
        # Потік для запуску сервера
        server_thread = threading.Thread(target=self.start_server)
        server_thread.daemon = True
        server_thread.start()

        # Потік для прослуховування мультикасту
        multicast_listen_thread = threading.Thread(target=self.multicast_listen)
        multicast_listen_thread.daemon = True
        multicast_listen_thread.start()

        # Після запуску сервера, починаємо надсилати оголошення
        threading.Thread(target=self.periodic_multicast_announce, daemon=True).start()

        # Періодична синхронізація з пірами
        self.start_periodic_sync()

        try:
            self.user_interface()
        except KeyboardInterrupt:
            print("\nShutting down gracefully...")
        finally:
            self.running = False

            
    def sync_with_peers(self):
        """Синхронізує стан блокчейну з пірами."""
        is_valid, invalid_blocks = self.chain.verify_chain_integrity()
        
        if not is_valid:
            print(f"Found invalid blocks: {invalid_blocks}")
            
            for invalid_block in invalid_blocks:
                block_index = invalid_block['index']
                print(f"Attempting to repair block at index {block_index}")
                
                # Запитуємо правильний блок у пірів
                correct_block = self.request_block_from_peers(block_index)
                print(correct_block)
                if correct_block:
                    # Виправляємо блок
                    if self.chain.repair_block(block_index, correct_block):
                        print(f"Successfully repaired block at index {block_index}")
                    else:
                        print(f"Failed to repair block at index {block_index}")
                else:
                    print(f"Could not obtain valid block from peers for index {block_index}")
        
        # Продовжуємо звичайну синхронізацію
        for peer_host, peer_port in self.peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer_host, peer_port))
                    
                    request = {
                        'type': 'get_chain',
                        'node_id': self.node_id
                    }
                    s.sendall(json.dumps(request).encode('utf-8'))
                    
                    response = json.loads(s.recv(16384).decode('utf-8'))
                    
                    if response['type'] == 'chain_data':
                        self.chain.resolve_conflicts(response['chain'])
                        
            except Exception as e:
                print(f"Failed to sync with peer {peer_host}:{peer_port}: {e}")

    def start_periodic_sync(self):
        """Запускає періодичну синхронізацію з пірами."""
        def sync_task():
            while self.running:
                try:
                    self.sync_with_peers()
                except Exception as e:
                    print(f"Error during sync: {e}")
                time.sleep(5)  # Синхронізація кожні 5 секунд
                
        sync_thread = threading.Thread(target=sync_task)
        sync_thread.daemon = True
        sync_thread.start()

    def request_block_from_peers(self, block_index):
        """Запитує конкретний блок у всіх пірів."""
        for peer_host, peer_port in self.peers:
            try:
                
                    
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    try:
                        s.connect((peer_host, peer_port))
                        print("Connected to peer:", peer_host, peer_port)
                        
                        request = {
                            'type': 'get_block',
                            'block_index': block_index,
                            'node_id': self.node_id
                        }
                        s.sendall(json.dumps(request).encode('utf-8'))

                        raw_response = s.recv(4096).decode('utf-8')
                        try:
                            response = json.loads(raw_response)
                        except json.JSONDecodeError:
                            print(f"Failed to decode JSON response from peer {peer_host}:{peer_port}")
                            return None

                        if response['type'] == 'block_data' and response.get('block'):
                            print("Received block data:", response['block'])
                            temp_block = Block(**response['block'])
                            if (temp_block.hash[:len(HASH_TARGET)] == HASH_TARGET and 
                                temp_block.hash == temp_block.calculate_hash()):
                                return response['block']
                            else:
                                print("Block validation failed for block at index", block_index)
                        else:
                            print(f"No valid block data received from {peer_host}:{peer_port}")
                    
                    except socket.error as e:
                        print(f"Socket error with peer {peer_host}:{peer_port}: {e}")
                    except Exception as e:
                        print(f"Unexpected error with peer {peer_host}:{peer_port}: {e}")

                return None

            except Exception as e:
                print(f"Failed to get block from peer {peer_host}:{peer_port}: {e}")
        
        return None
    
    def multicast_listen(self):
        """Прослуховування мультикаст-групи для пошуку інших нод."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Прив'язуємо сокет до всіх інтерфейсів і порту MULTICAST_PORT
        sock.bind(('', MULTICAST_PORT))

        # Додаємо сокет у мультикаст-групу
        group = socket.inet_aton(MULTICAST_GROUP)
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        while self.running:
            try:
                data, address = sock.recvfrom(BUFFER_SIZE)
                message = json.loads(data.decode('utf-8'))

                if message['type'] == 'node_announcement':
                    peer_host = address[0]
                    peer_port = message['port']
                    
                    # Skip if this is our own announcement
                    if (peer_host == self.host or 
                        peer_host == 'localhost' or 
                        peer_host == '127.0.0.1' or
                        message['node_id'] == self.node_id):
                        continue
                    
                    peer_info = (peer_host, peer_port)
                    if peer_info not in self.peers:
                        self.peers.append(peer_info)
                        print(f"Found new peer: {peer_info}")
                        
            except Exception as e:
                if self.running:  # Ігноруємо помилки при завершенні роботи
                    print(f"Multicast listen error: {e}")
        sock.close()

    def multicast_announce(self):
        """Відправлення повідомлення про свою доступність у мультикаст-групу."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        message = {
            'type': 'node_announcement',
            'node_id': self.node_id,
            'host': self.host,
            'port': self.port
        }

        try:
            sock.sendto(json.dumps(message).encode('utf-8'), (MULTICAST_GROUP, MULTICAST_PORT))
            print("Sent multicast announcement.")
        except Exception as e:
            print(f"Multicast announce error: {e}")
        finally:
            sock.close()

    def periodic_multicast_announce(self):
        """Періодичне надсилання мультикаст-оголошень."""
        while self.running:
            self.multicast_announce()
            time.sleep(10)  # Відправляємо оголошення кожні 10 секунд

    def _get_file_transfer_peers(self):
        """Convert discovery peers to file transfer peers, excluding self"""
        discovery_peers = NetworkConfig.get_peers(self.node_id)
        
        # Filter out own address by checking both host and node_id
        filtered_peers = []
        own_ip = NetworkConfig._discovery._get_my_ip()
        
        for host, port in discovery_peers:
            # Skip if this is our own address
            if host == own_ip or host == self.host or host == 'localhost' or host == '127.0.0.1':
                print(f"Skipping own address: {host}:{port}")
                continue
            
            # Convert discovery port to file transfer port
            file_transfer_port = NetworkConfig._discovery.get_file_transfer_port(port)
            filtered_peers.append((host, file_transfer_port))
        
        print(f"Filtered peers (excluding self): {filtered_peers}")
        return filtered_peers