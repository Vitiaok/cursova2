# node.py
import socket
import threading
import json
from chain import Chain
from block import Block
from config import NetworkConfig
import time

class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        self.host, self.port = NetworkConfig.NODES[node_id]
        self.chain = Chain()
        self.peers = NetworkConfig.get_peers(node_id)
        self.running = True

    import time

    def broadcast_block_for_validation(self, block):
        """Відправляє блок на валідацію всім пірам."""
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

                        # Очікуємо відповідь
                        response = json.loads(s.recv(4096).decode('utf-8'))
                        print(f"Validation response from {peer_host}:{peer_port}: {response}")
                        validation_responses.append(response)
                        if all(res['type'] == 'validation_success' for res in validation_responses):
                            print("Block validated by all peers, adding to local chain.")
                            self.chain.add_validated_block(block)
                        else:
                            print("Block validation failed. Not adding to local chain.")
                        connected = True  # Якщо підключення було успішним, вийдемо з циклу
                except Exception as e:
                    print(f"Failed to send block to {peer_host}:{peer_port}: {e}")
                    print("Retrying in 5 seconds...")
                    time.sleep(5)  # Затримка перед наступною спробою


        

    def handle_client(self, client_socket, addr):
        """Обробляє вхідні з'єднання."""
        try:
            data = client_socket.recv(4096).decode('utf-8')
            message = json.loads(data)
            
            if message['type'] == 'validate_block':
                block = Block(**message['block'])
                validator_id = message['validator']
                
                if self.chain.validate_block(block, validator_id):
                    response = {'type': 'validation_success', 'block_hash': block.hash}
                    
                else:
                    response = {'type': 'validation_failed', 'block_hash': block.hash}
                    
                client_socket.sendall(json.dumps(response).encode('utf-8'))
                
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()

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

    def create_and_broadcast_block(self, data):
        """Створює новий блок та відправляє його на валідацію."""
        new_block = self.chain.create_block(data)
        self.broadcast_block_for_validation(new_block)
       

    def user_interface(self):
        """Інтерфейс користувача для взаємодії з нодою."""
        while self.running:
            command = input("\nEnter command (n: new block, c: show chain, q: quit): ").strip().lower()
            
            if command == 'n':
                data = input("Enter data for the new block: ")
                self.create_and_broadcast_block(data)
            
            elif command == 'c':
                #self.chain.remove_block_by_index(3)
                
                chain = self.chain.get_chain()
                print("\nCurrent Blockchain:")
                for block in chain:
                    print(f"\nBlock #{block.index}")
                    print(f"Timestamp: {block.timestamp}")
                    print(f"Data: {block.data}")
                    print(f"Hash: {block.hash}")
                    print(f"Previous Hash: {block.previous_hash}")
            
            elif command == 'q':
                print("Shutting down...")
                self.running = False
                break
            
            else:
                print("Invalid command. Please use 'n' for new block, 'c' to show chain, or 'q' to quit.")

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