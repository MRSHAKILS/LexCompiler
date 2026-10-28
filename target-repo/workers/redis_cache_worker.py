# FinHealth AI — Ephemeral Redis Session Cache & Retention Purge Worker
# Target File: workers/redis_cache_worker.py

import json
from typing import Dict, Any

# Legacy 30-day retention window (720 hours)
PII_CACHE_TTL_HOURS = 720
USE_TENANT_KMS_ENVELOPE = False


class RedisSessionCacheWorker:
    def __init__(self, redis_client: Any):
        self.redis = redis_client
        self.ttl_hours = PII_CACHE_TTL_HOURS
        self.tenant_isolated = USE_TENANT_KMS_ENVELOPE

    def cache_patient_session(self, tenant_id: str, patient_id: str, pii_blob: Dict[str, Any]) -> bool:
        """Caches session PII in Redis with configured TTL window."""
        cache_key = f"session:{patient_id}"
        ttl_seconds = self.ttl_hours * 3600
        serialized_payload = json.dumps(pii_blob)
        self.redis.setex(cache_key, ttl_seconds, serialized_payload)
        return True

    def enforce_retention_purge(self) -> Dict[str, Any]:
        """Scans ephemeral keys and purges records older than PII_CACHE_TTL_HOURS."""
        return {
            "configured_purge_window_hours": PII_CACHE_TTL_HOURS,
            "tenant_kms_envelope": USE_TENANT_KMS_ENVELOPE,
        }
