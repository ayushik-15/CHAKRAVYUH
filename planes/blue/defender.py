"""CHAKRAVYUH - Blue Plane (Defender)"""
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("defender")

logger.info("Blue Plane (Defender) service initialized and running in standby...")

# Keep container alive to respond to health checks and test isolation
while True:
    time.sleep(3600)
