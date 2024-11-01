import socket
import threading
import json

class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = []  # список сусідніх вузлів
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
        if request:
            print(f"Received: {request}")
            response = f"Echo: {request}"
            client_socket.send(response.encode('utf-8'))
        client_socket.close()

    def connect_to_peer(self, peer_host, peer_port):
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            peer_socket.connect((peer_host, peer_port))
            self.peers.append((peer_host, peer_port))
            print(f"Connected to peer: {peer_host}:{peer_port}")
        except ConnectionRefusedError:
            print(f"Could not connect to {peer_host}:{peer_port}")

    def broadcast(self, message):
        for peer in self.peers:
            try:
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect(peer)
                peer_socket.send(message.encode('utf-8'))
                peer_socket.close()
            except Exception as e:
                print(f"Error sending to {peer}: {e}")

if __name__ == "__main__":
    # Створюємо вузол
    node = Node("127.0.0.1", 5000)  # Змініть порт для інших вузлів
    node.start()
    
    # Підключення до інших вузлів
    node.connect_to_peer("127.0.0.1", 5001)
    node.connect_to_peer("127.0.0.1", 5002)
    node.connect_to_peer("127.0.0.1", 5003)

    # Залишаємо програму запущеною
    while True:
        # Надсилаємо повідомлення (наприклад, при натисканні Enter)
        input_message = input("Enter message to broadcast: ")
        node.broadcast(input_message)
