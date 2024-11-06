import socket
import threading
import json
from chain import Chain  # Імпортуємо клас Chain з chain.py
from block import Block

class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = []  # список сусідніх вузлів
        self.chain = Chain()  # Ініціалізація блокчейну
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Node started at {self.host}:{self.port}")

    def start(self):
        threading.Thread(target=self.accept_connections).start()

    def accept_connections(self):
        while True:
            client_socket, address = self.server.accept()
            print(f"Connection from {address} has been established!")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        request = client_socket.recv(1024).decode('utf-8')
        if request == "REQUEST_BLOCKCHAIN":
            self.send_blockchain(client_socket)
        else:
            self.receive_blockchain(client_socket)
        client_socket.close()

    def connect_to_peer(self, peer_host, peer_port):
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            peer_socket.connect((peer_host, peer_port))
            self.peers.append((peer_host, peer_port))
            print(f"Connected to peer: {peer_host}:{peer_port}")
            self.request_blockchain(peer_socket)
        except ConnectionRefusedError:
            print(f"Could not connect to {peer_host}:{peer_port}")

    def request_blockchain(self, peer_socket):
        peer_socket.sendall("REQUEST_BLOCKCHAIN".encode('utf-8'))
        print("Blockchain request sent.")

    def send_blockchain(self, client_socket):
        blockchain_data = json.dumps([block.__dict__ for block in self.chain.getChain()])
        client_socket.sendall(blockchain_data.encode('utf-8'))
        print("Blockchain sent successfully.")

    def receive_blockchain(self, client_socket):
        data = client_socket.recv(4096).decode('utf-8')
        if data:
            blockchain_data = json.loads(data)
            self.chain.blockchain = [Block(**block) for block in blockchain_data]
            print("Blockchain received and updated.")

    def broadcast(self, message):
        for peer in self.peers:
            try:
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect(peer)
                peer_socket.send(message.encode('utf-8'))
                peer_socket.close()
            except Exception as e:
                print(f"Error sending to {peer}: {e}")

    def send_blockchain_to_peers(self):
        for peer in self.peers:
            try:
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect(peer)
                self.send_blockchain(peer_socket)
                peer_socket.close()
            except Exception as e:
                print(f"Error sending blockchain to {peer}: {e}")

    def create_block(self, data):
        self.chain.addBlock(data)  # Виклик методу для додавання блоку з Chain
        print(f"New block created: {len(self.chain.getChain()) - 1}")

if __name__ == "__main__":
    node = Node("192.168.56.1", 5000)  # Змініть IP на вашу локальну адресу
    node.start()

    # Підключення до інших вузлів
    node.connect_to_peer("192.168.2.15", 5001)

    # Залишаємо програму запущеною
    while True:
        input_message = input("Enter '1' to create a new block, '2' to send blockchain to peers: ")
        if input_message == '1':
            data = input("Enter data for the new block: ")
            node.create_block(data)
        elif input_message == '2':
            node.send_blockchain_to_peers()
        else:
            print("Invalid input. Please try again.")








