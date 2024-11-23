# config.py
class NetworkConfig:
    # Налаштування мережі
    NODES = {
        "node1": ("192.168.0.103", 5000),
        "node2": ("192.168.0.105", 5001),
        # Додайте інші ноди за необхідності
    }

    @classmethod
    def get_peers(cls, node_id):
        """Повертає список всіх пірів для даної ноди."""
        return [(host, port) for nid, (host, port) in cls.NODES.items() if nid != node_id]