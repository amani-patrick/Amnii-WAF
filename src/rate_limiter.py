import redis

class RateLimiter:
    """Rate limiter using Redis"""
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.limit = 100 
        self.window = 600 

    def is_rate_limited(self, ip: str) -> bool:
        key = f"rate_limit:{ip}"
        count = self.redis_client.get(key)

        if count and int(count) >= self.limit:
            return True

        self.redis_client.incr(key, 1)
        self.redis_client.expire(key, self.window)
        return False
