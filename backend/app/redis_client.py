import json
import logging
import threading

logger = logging.getLogger("SOC-PubSub")

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis library not found. Run 'pip install redis' to enable Redis Pub/Sub.")

from backend.app import config

# Thread-safe Local PubSub Fallback
class InMemoryBroker:
    def __init__(self):
        self._subscribers = []
        self._lock = threading.Lock()
        
    def subscribe(self, callback):
        with self._lock:
            self._subscribers.append(callback)
            
    def publish(self, channel: str, message: str):
        with self._lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(message)
            except Exception as e:
                logger.error(f"Error executing callback in local broker: {e}")

_local_broker = InMemoryBroker()

class PubSubClient:
    def __init__(self):
        self.redis_client = None
        self.use_fallback = True
        
        if REDIS_AVAILABLE:
            try:
                logger.info(f"Attempting connection to Redis broker at {config.REDIS_URL}...")
                self.redis_client = redis.from_url(config.REDIS_URL, decode_responses=True)
                # Test connection
                self.redis_client.ping()
                self.use_fallback = False
                logger.info("Successfully connected to Redis broker!")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}. Falling back to in-memory message broker.")
                
    def publish(self, channel: str, message_dict: dict):
        message_str = json.dumps(message_dict)
        if self.use_fallback:
            _local_broker.publish(channel, message_str)
        else:
            try:
                self.redis_client.publish(channel, message_str)
            except Exception as e:
                logger.error(f"Redis publish failed: {e}. Falling back to local broker.")
                _local_broker.publish(channel, message_str)
                
    def subscribe(self, channel: str, callback):
        """
        Subscribes a callback to a channel.
        Callback must accept a single string argument (the message payload).
        """
        if self.use_fallback:
            _local_broker.subscribe(callback)
        else:
            # Run Redis subscription loop in a background thread
            def listen():
                try:
                    pubsub = self.redis_client.pubsub()
                    pubsub.subscribe(channel)
                    logger.info(f"Subscribed to Redis channel '{channel}'")
                    for message in pubsub.listen():
                        if message['type'] == 'message':
                            callback(message['data'])
                except Exception as e:
                    logger.error(f"Redis subscription listen failed: {e}. Switching callback to local broker.")
                    _local_broker.subscribe(callback)

            t = threading.Thread(target=listen, daemon=True)
            t.start()

# Export a single global PubSub Client instance
pubsub_client = PubSubClient()
