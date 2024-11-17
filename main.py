from config import NetworkConfig
from node import Node
# main.py
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python main.py <node_id>")
        print("Available nodes:", list(NetworkConfig.NODES.keys()))
        sys.exit(1)
        
    node_id = sys.argv[1]
    if node_id not in NetworkConfig.NODES:
        print(f"Invalid node_id. Available nodes: {list(NetworkConfig.NODES.keys())}")
        sys.exit(1)
        
    node = Node(node_id)
    node.start()