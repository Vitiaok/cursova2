from Network import NetworkDiscovery

class NetworkConfig:
    _discovery = None  # Set initial value to None
    
    @classmethod
    def initialize(cls, node_id):
        """Initialize network discovery"""
        if cls._discovery is None:
            cls._discovery = NetworkDiscovery()  # Instantiate only once
        cls._discovery.start(node_id)
    
    @classmethod
    def get_node_info(cls, node_id):
        """Get host and port for specific node"""
        if node_id in cls._discovery.nodes:
            return cls._discovery.nodes[node_id]
        return cls._discovery._get_my_ip(), cls._discovery.DISCOVERY_PORT
    
    @classmethod
    def get_peers(cls, node_id):
        """Get peers for the given node, excluding self"""
        all_peers = cls._discovery.get_peers(node_id)
        own_ip = cls._discovery._get_my_ip()
        
        # Filter out own address
        filtered_peers = [
            (host, port) for host, port in all_peers 
            if host != own_ip and host != 'localhost' and host != '127.0.0.1'
        ]
        
        print(f"Filtered discovery peers (excluding self): {filtered_peers}")
        return filtered_peers