from __future__ import annotations
from functools import lru_cache
import redis

from app.config import settings

@lru_cache(maxsize=1)
def get_redis() -> redis.Redis:
    return redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
    )

def blacklist_jti(jti: str, ttl_sec: int) -> None:
    if ttl_sec <= 0:
        return
    get_redis().setex(f"revoked:{jti}", ttl_sec, "1")

def is_blacklisted(jti: str) -> bool:
    return get_redis().exists(f"revoked:{jti}") == 1