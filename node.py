import socket
import threading
from chain import Chain

class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.chain = Chain()
        self.peers = [("192.168.2.15", 5001)]  # Додайте інші ноди тут

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr} has been established!")
            self.chain.receive_blockchain(client_socket)
            client_socket.close()

    def add_and_broadcast_block(self, data):
        self.chain.add_block(data)
        for peer_host, peer_port in self.peers:
            self.chain.send_blockchain(peer_host, peer_port)
        print("New block created and broadcasted!")

    def user_interface(self):
        while True:
            command = input("Enter 'n' to create a new block or 'q' to quit: ").strip().lower()
            if command == 'n':
                data = input("Enter data for the new block: ")
                self.add_and_broadcast_block(data)
            elif command == 'q':
                print("Exiting.")
                break
            else:
                print("Invalid command. Please enter 'n' to create a new block or 'q' to quit.")

if __name__ == "__main__":
    # Створення та запуск ноди
    node = Node("192.168.2.13", 5000)
    threading.Thread(target=node.start_server, daemon=True).start()

    # Інтерфейс користувача для створення блоку
    node.user_interface()























