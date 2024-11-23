import socket
import netifaces
import threading
import json
from typing import Dict, List, Tuple
import time

class NetworkDiscovery:
    DISCOVERY_PORT = 5000  # Base port for node discovery
    MAX_NODES = 10        # Maximum number of ports to scan after base port
    FILE_TRANSFER_PORT_OFFSET = 1000

    def __init__(self):
        self.nodes: Dict[str, Tuple[str, int]] = {}
        self.my_ip = self._get_my_ip()
        self.discovery_thread = None
        self.running = True
        # _discovery instantiation removed here

    def _get_my_ip(self) -> str:
        """Get the local IP address of the machine."""
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                
                # Look for IPv4 addresses
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        # Skip localhost
                        if not ip.startswith('127.'):
                            return ip
                            
        except Exception as e:
            print(f"Error getting IP address: {e}")
            return socket.gethostbyname(socket.gethostname())

    def discover_nodes(self) -> Dict[str, Tuple[str, int]]:
        """Scan the network for other blockchain nodes."""
        # Get the network prefix (e.g., "192.168.1.")
        network_prefix = '.'.join(self.my_ip.split('.')[:-1]) + '.'
        
        discovered_nodes = {}
        
        def try_connect(ip: str, port: int):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)  # Short timeout for quick scanning
                    s.connect((ip, port))
                    
                    # Send discovery request
                    request = {
                        'type': 'discovery',
                        'sender_ip': self.my_ip
                    }
                    s.sendall(json.dumps(request).encode('utf-8'))
                    
                    # Receive response
                    response = json.loads(s.recv(1024).decode('utf-8'))
                    if response.get('type') == 'discovery_response':
                        node_id = response.get('node_id')
                        discovered_nodes[node_id] = (ip, port)
                        print(f"Discovered node {node_id} at {ip}:{port}")
                        
            except (socket.timeout, ConnectionRefusedError):
                pass
            except Exception as e:
                print(f"Error scanning {ip}:{port}: {e}")

        # Scan local network
        threads = []
        for i in range(1, 255):  # Scan all possible IP addresses in subnet
            ip = network_prefix + str(i)
            if ip != self.my_ip:  # Don't scan own IP
                for port_offset in range(self.MAX_NODES):
                    port = self.DISCOVERY_PORT + port_offset
                    thread = threading.Thread(target=try_connect, args=(ip, port))
                    thread.start()
                    threads.append(thread)
        
        # Wait for all scans to complete
        for thread in threads:
            thread.join()
            
        return discovered_nodes

    def start_discovery_server(self, node_id: str):
        """Start a server to respond to discovery requests."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Find available port
        for port_offset in range(self.MAX_NODES):
            try:
                port = self.DISCOVERY_PORT + port_offset
                server_socket.bind((self.my_ip, port))
                self.nodes[node_id] = (self.my_ip, port)
                break
            except OSError:
                continue
        
        server_socket.listen(5)
        print(f"Discovery server started on {self.my_ip}:{port}")

        while self.running:
            try:
                client_socket, addr = server_socket.accept()
                threading.Thread(target=self._handle_discovery_request,
                              args=(client_socket, node_id)).start()
            except Exception as e:
                if self.running:
                    print(f"Discovery server error: {e}")

    def _handle_discovery_request(self, client_socket: socket.socket, node_id: str):
        """Handle incoming discovery requests."""
        try:
            data = client_socket.recv(1024).decode('utf-8')
            message = json.loads(data)
            
            if message.get('type') == 'discovery':
                response = {
                    'type': 'discovery_response',
                    'node_id': node_id,
                    'port': self.nodes[node_id][1]
                }
                client_socket.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            print(f"Error handling discovery request: {e}")
        finally:
            client_socket.close()

    def start(self, node_id: str):
        """Start the discovery service."""
        # Start discovery server
        self.discovery_thread = threading.Thread(target=self.start_discovery_server,
                                              args=(node_id,))
        self.discovery_thread.daemon = True
        self.discovery_thread.start()
        
        # Initial discovery
        discovered = self.discover_nodes()
        self.nodes.update(discovered)
        
        # Start periodic discovery
        def periodic_discovery():
            while self.running:
                time.sleep(30)  # Run discovery every 30 seconds
                new_nodes = self.discover_nodes()
                self.nodes.update(new_nodes)
        
        discovery_thread = threading.Thread(target=periodic_discovery)
        discovery_thread.daemon = True
        discovery_thread.start()

    def stop(self):
        """Stop the discovery service."""
        self.running = False

    def get_peers(self, node_id: str) -> List[Tuple[str, int]]:
        """Get list of peer addresses excluding the given node."""
        return [(host, port) for nid, (host, port) in self.nodes.items() 
                if nid != node_id]
    
    @classmethod
    def get_file_transfer_port(cls, discovery_port):
        """Calculate file transfer port based on discovery port"""
        return discovery_port + cls.FILE_TRANSFER_PORT_OFFSET