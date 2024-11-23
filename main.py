from config import NetworkConfig
from node import Node
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python main.py <node_id>")
        sys.exit(1)
        
    node_id = sys.argv[1]
    
    # Initialize network discovery
    NetworkConfig.initialize(node_id)
    
    # Small delay to allow initial discovery
    import time
    time.sleep(2)
    
    node = Node(node_id)
    try:
        print(f"Node started with:")
        print(f"Discovery port: {node.discovery_port}")
        print(f"File transfer port: {node.file_transfer_port}")
        node.start()
    except KeyboardInterrupt:
        print("\nShutting down node...")
        node.running = False