import socket
import threading
import json
from block import Block
from chain import Chain  # Імпорт Chain для управління блокчейном

BLOCKCHAIN_FILE = "received_blockchain.json"

class ReceivingNode:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.chain = Chain()  # Використовуємо Chain для зберігання отриманого блокчейну
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Receiving Node started at {self.host}:{self.port}")

    def start(self):
        threading.Thread(target=self.accept_connections).start()

    def accept_connections(self):
        while True:
            client_socket, address = self.server.accept()
            print(f"Connection from {address} has been established!")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            data = client_socket.recv(4096).decode('utf-8')
            if data:
                blockchain_data = json.loads(data)
                self.chain.blockchain = [Block(**block) for block in blockchain_data]
                self.save_chain_to_file()
                print("Blockchain received and saved successfully.")
        except json.JSONDecodeError:
            print("Error decoding the received blockchain data.")
        finally:
            client_socket.close()

    def save_chain_to_file(self):
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump(
                [block.__dict__ for block in self.chain.getChain()],
                f,
                indent=4,
                sort_keys=True
            )
        print(f"Blockchain saved to {BLOCKCHAIN_FILE}")

if __name__ == "__main__":
    receiving_node = ReceivingNode("192.168.0.101", 5001)  # Змінити IP на відповідну адресу
    receiving_node.start()

    # Програма залишається запущеною для отримання даних
    while True:
        pass
