from Network import NetworkDiscovery
import json

class NetworkConfig:
    _discovery = None  # Set initial value to None
    
    @classmethod
    def initialize(cls, node_id):
        """Initialize network discovery"""
        if cls._discovery is None:
            cls._discovery = NetworkDiscovery()  # Instantiate only once
            try:
                cls._discovery.start(node_id)
            except Exception as e:
                print(f"Error initializing network discovery: {e}")
                raise
    
    @classmethod
    def get_node_info(cls, node_id):
        """
        Get host and port for specific node
        
        Args:
            node_id (str): The ID of the node
            
        Returns:
            tuple: (host, port) for the specified node
        """
        try:
            if not cls._discovery:
                raise RuntimeError("NetworkConfig not initialized. Call initialize() first.")
                
            if node_id in cls._discovery.nodes:
                return cls._discovery.nodes[node_id]
            
            # Fallback to default values
            return cls._discovery._get_my_ip(), cls._discovery.DISCOVERY_PORT
            
        except Exception as e:
            print(f"Error getting node info for {node_id}: {e}")
            raise
    
    @classmethod
    def get_peers(cls, node_id):
        """
        Get peers for the given node, excluding self
        
        Args:
            node_id (str): The ID of the node
            
        Returns:
            list: List of (host, port) tuples for peer nodes
        """
        try:
            if not cls._discovery:
                raise RuntimeError("NetworkConfig not initialized. Call initialize() first.")
                
            all_peers = cls._discovery.get_peers(node_id)
            own_ip = cls._discovery._get_my_ip()
            
            # Filter out own address and local addresses
            filtered_peers = [
                (host, port) for host, port in all_peers 
                if host != own_ip and 
                host != 'localhost' and 
                host != '127.0.0.1'
            ]
            
            return filtered_peers
            
        except Exception as e:
            print(f"Error getting peers for {node_id}: {e}")
            raise
    
    @classmethod
    def serialize_node_data(cls, data):
        """
        Safely serialize node data to JSON
        
        Args:
            data: The data to serialize
            
        Returns:
            str: JSON string representation of the data
        """
        try:
            return json.dumps(data, separators=(',', ':'))
        except Exception as e:
            print(f"Error serializing node data: {e}")
            raise
    
    @classmethod
    def deserialize_node_data(cls, json_str):
        """
        Safely deserialize JSON node data
        
        Args:
            json_str (str): JSON string to deserialize
            
        Returns:
            dict: Deserialized data
        """
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"Error deserializing JSON data: {e}")
            # Log the problematic JSON string (first 100 chars)
            print(f"Problematic JSON (truncated): {json_str[:100]}...")
            raise
        except Exception as e:
            print(f"Unexpected error deserializing data: {e}")
            raise
    
    @classmethod
    def validate_peer(cls, host, port):
        """
        Validate peer connection information
        
        Args:
            host (str): Peer host address
            port (int): Peer port number
            
        Returns:
            bool: True if peer info is valid, False otherwise
        """
        try:
            if not isinstance(host, str) or not host:
                return False
                
            if not isinstance(port, int) or port < 1 or port > 65535:
                return False
                
            # Check if host is a valid IP address format
            parts = host.split('.')
            if len(parts) != 4:
                return False
                
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return False
                    
            return True
            
        except Exception:
            return False