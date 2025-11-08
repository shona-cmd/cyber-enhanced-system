c.#!/usr/bin/env python3

import logging
from naashon_secure_iot.config import Config
from naashon_secure_iot.layers.network import NetworkLayer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create config and network layer
config = Config()
network_layer = NetworkLayer(config, logger)

# Test get_network_status
status = network_layer.get_network_status()
print("Network Status:")
for key, value in status.items():
    print(f"  {key}: {value}")

# Test connectivity check
connectivity = network_layer._check_connectivity()
print(f"\nConnectivity Status: {connectivity}")
