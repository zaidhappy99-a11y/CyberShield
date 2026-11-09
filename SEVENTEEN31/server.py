"""
NetSentinel - Root Launch Server
Run this directly to start the SOC Dashboard and Network Detection Engine.
"""

import os
import sys

# Add detector directory to path
curr_dir = os.path.dirname(os.path.abspath(__file__))
detector_dir = os.path.join(curr_dir, "detector")
if detector_dir not in sys.path:
    sys.path.insert(0, detector_dir)

from bridge_server import run_bridge_server

if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_bridge_server(port)
