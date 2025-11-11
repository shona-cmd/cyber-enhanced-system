import logging
from .base import Layer

logger = logging.getLogger(__name__)

class NetworkLayer(Layer):
    def __init__(self, protocol="TCP"):
        super().__init__()
        self.protocol = protocol
        logger.info(f"NetworkLayer initialized with {protocol}")

    def send_data(self, data):
        logger.debug(f"Sending data via {self.protocol}: {data}")
        return f"{self.protocol}-sent: {data}"

def main():
    layer = NetworkLayer("TCP")  # or "UDP"
    result = layer.send_data("Hello IoT")
    print(result)

if __name__ == "__main__":
    main()
