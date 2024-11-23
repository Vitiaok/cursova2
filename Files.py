import os
import hashlib
import base64
import json
import socket
import time
from typing import Dict, Tuple

class FileTransfer:
    CHUNK_SIZE = 8192
    FILE_STORAGE = "node_files"
    TRANSFER_TIMEOUT = 60  # timeout in seconds

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
            "file_size": os.path.getsize(file_path),
            "timestamp": time.time()
        }

class FileHandler:
    def __init__(self, node):
        self.node = node
        FileTransfer.prepare_storage()
        self.transfer_status: Dict[str, bool] = {}

    def send_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                print(f"Error: File {file_path} not found")
                return False

            # Create metadata
            metadata = FileTransfer.create_file_metadata(file_path)
            print(f"Preparing to send file: {metadata['filename']}")
            print(f"File size: {metadata['file_size']} bytes")
            print(f"File hash: {metadata['file_hash']}")

            # Get current peers
            peers = self.node.peers
            if not peers:
                print("No peers found to send file to")
                return False

            print(f"Found {len(peers)} peers to send file to")
            
            # Broadcast file to all peers
            success = self._broadcast_file(file_path, metadata)
            
            if success:
                file_data = {
                    **metadata,
                    "sender_node": self.node.node_id,
                    "transfer_status": "completed"
                }
                
                # Create blockchain record
                self.node.create_and_broadcast_block(json.dumps(file_data))
                print(f"File {metadata['filename']} successfully transferred and recorded in blockchain")
                return True
            else:
                print("File transfer failed")
                return False

        except Exception as e:
            print(f"Error in send_file: {e}")
            return False

    def _broadcast_file(self, file_path, metadata):
        successful_transfers = 0
        total_peers = len(self.node.peers)

        for peer_host, peer_port in self.node.peers:
            try:
                print(f"Attempting to connect to peer {peer_host}:{peer_port} (file transfer port)")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(FileTransfer.TRANSFER_TIMEOUT)
                    s.connect((peer_host, peer_port))
                    
                    # Send metadata first
                    metadata_msg = {
                        "type": "file_transfer",
                        "metadata": metadata,
                        "sender_node": self.node.node_id
                    }
                    s.sendall(json.dumps(metadata_msg).encode('utf-8'))
                    print(f"Sent metadata to {peer_host}:{peer_port}")
                    
                    # Wait for ready signal with timeout
                    s.settimeout(5)  # 5 seconds timeout for ready signal
                    try:
                        response = s.recv(1024).decode('utf-8')
                        if response != "ready":
                            print(f"Peer {peer_host}:{peer_port} not ready. Response: {response}")
                            continue
                    except socket.timeout:
                        print(f"Timeout waiting for ready signal from {peer_host}:{peer_port}")
                        continue

                    # Reset timeout for file transfer
                    s.settimeout(FileTransfer.TRANSFER_TIMEOUT)
                    
                    # Send file content
                    bytes_sent = 0
                    file_size = os.path.getsize(file_path)
                    with open(file_path, 'rb') as f:
                        while bytes_sent < file_size:
                            chunk = f.read(FileTransfer.CHUNK_SIZE)
                            if not chunk:
                                break
                            s.sendall(chunk)
                            bytes_sent += len(chunk)
                            progress = (bytes_sent / file_size) * 100
                            print(f"\rSending to {peer_host}:{peer_port}: {progress:.1f}%", end="")
                    
                    print(f"\nFile successfully sent to {peer_host}:{peer_port}")
                    successful_transfers += 1

            except socket.timeout:
                print(f"Connection to {peer_host}:{peer_port} timed out")
            except ConnectionRefusedError:
                print(f"Connection refused by {peer_host}:{peer_port}")
            except Exception as e:
                print(f"Error sending file to {peer_host}:{peer_port}: {e}")

        return successful_transfers > 0

    def receive_file(self, client_socket, metadata):
        try:
            filename = metadata["filename"]
            expected_hash = metadata["file_hash"]
            file_size = metadata["file_size"]
            sender_node = metadata.get("sender_node", "unknown")
            
            print(f"\nReceiving file {filename} from node {sender_node}")
            print(f"Expected size: {file_size} bytes")
            print(f"Expected hash: {expected_hash}")
            
            file_path = os.path.join(FileTransfer.FILE_STORAGE, filename)
            
            # Send ready signal
            client_socket.sendall("ready".encode('utf-8'))
            
            # Receive file content
            received_size = 0
            with open(file_path, 'wb') as f:
                while received_size < file_size:
                    chunk = client_socket.recv(min(FileTransfer.CHUNK_SIZE, file_size - received_size))
                    if not chunk:
                        break
                    f.write(chunk)
                    received_size += len(chunk)
                    progress = (received_size / file_size) * 100
                    print(f"\rReceiving: {progress:.1f}%", end="")
            
            print("\nVerifying file integrity...")
            received_hash = FileTransfer.calculate_file_hash(file_path)
            
            if received_hash != expected_hash:
                print("Error: File hash mismatch")
                os.remove(file_path)
                return False
                
            print(f"File {filename} successfully received and verified")
            return True
            
        except Exception as e:
            print(f"Error receiving file: {e}")
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)
            return False