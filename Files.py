import os
import hashlib
import base64
import json
import socket
import time

class FileTransfer:
    CHUNK_SIZE = 8192
    FILE_STORAGE = "node_files"

    @staticmethod
    def calculate_file_hash(file_path):
        
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def prepare_storage():
        
        if not os.path.exists(FileTransfer.FILE_STORAGE):
            os.makedirs(FileTransfer.FILE_STORAGE)

    @staticmethod
    def create_file_metadata(file_path):
        
        file_hash = FileTransfer.calculate_file_hash(file_path)
        return {
            "filename": os.path.basename(file_path),
            "file_hash": file_hash,
            "file_size": os.path.getsize(file_path)
        }

class FileHandler:
    def __init__(self, node):
        self.node = node
        FileTransfer.prepare_storage()

    def send_file(self, file_path):

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found")

        
        metadata = FileTransfer.create_file_metadata(file_path)
        
        
        success = self._broadcast_file(file_path, metadata)
        
        if success:
            
            file_data = metadata
                
            
            self.node.create_and_broadcast_block(json.dumps(file_data))
            return True
        return False

    def _broadcast_file(self, file_path, metadata):
        for peer_host, peer_port in self.node.peers:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer_host, peer_port))
                    
                    
                    metadata_msg = {
                        "type": "file_transfer",
                        "metadata": metadata
                    }
                    s.sendall(json.dumps(metadata_msg).encode('utf-8'))
                    
                    
                    response = s.recv(1024).decode('utf-8')
                    if response != "ready":
                        continue

                    
                    with open(file_path, 'rb') as f:
                        while True:
                            chunk = f.read(FileTransfer.CHUNK_SIZE)
                            if not chunk:
                                break
                            s.sendall(chunk)
                            
                    print(f"File sent to {peer_host}:{peer_port}")
            except Exception as e:
                print(f"Failed to send file to {peer_host}:{peer_port}: {e}")
                print("Retrying in 5 seconds...")
                time.sleep(5)
                
        return True

    def receive_file(self, client_socket, metadata):
        try:
            filename = metadata["filename"]
            expected_hash = metadata["file_hash"]
            file_size = metadata["file_size"]
            
            file_path = os.path.join(FileTransfer.FILE_STORAGE, filename)
            
            
            client_socket.sendall("ready".encode('utf-8'))
            
           
            received_size = 0
            with open(file_path, 'wb') as f:
                while received_size < file_size:
                    chunk = client_socket.recv(min(FileTransfer.CHUNK_SIZE, file_size - received_size))
                    if not chunk:
                        break
                    f.write(chunk)
                    received_size += len(chunk)
            
           
            received_hash = FileTransfer.calculate_file_hash(file_path)
            if received_hash != expected_hash:
                os.remove(file_path)
                raise ValueError("File hash mismatch")
                
            print(f"File {filename} received and verified")
            return True
            
        except Exception as e:
            print(f"Error receiving file: {e}")
            return False