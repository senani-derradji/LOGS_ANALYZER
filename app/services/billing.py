from typing import Optional
from app.core.config import settings


STRIPE_PRICES = {
    "pro": "price_pro_monthly",
    "enterprise": "price_enterprise_monthly",
}

TIER_FEATURES = {
    "free": {
        "monthly_logs": 100,
        "storage_mb": 100,
        "api_keys": 0,
        "webhooks": 0,
    },
    "pro": {
        "monthly_logs": 1000,
        "storage_mb": 1024,
        "api_keys": 5,
        "webhooks": 3,
    },
    "enterprise": {
        "monthly_logs": 999999999,
        "storage_mb": 10240,
        "api_keys": -1,
        "webhooks": -1,
    },
}


class BillingService:
    def __init__(self):
        self.stripe_enabled = False
        self.stripe_api_key = None

    def is_enabled(self) -> bool:
        return self.stripe_enabled and bool(self.stripe_api_key)

    async def create_customer(self, email: str, name: str) -> Optional[str]:
        if not self.is_enabled():
            return None
        pass

    async def create_subscription(
        self, customer_id: str, tier: str
    ) -> Optional[dict]:
        if not self.is_enabled():
            return None
        pass

    async def cancel_subscription(self, subscription_id: str) -> Optional[dict]:
        if not self.is_enabled():
            return None
        pass

    async def create_portal_session(
        self, customer_id: str
    ) -> Optional[str]:
        if not self.is_enabled():
            return None
        pass

    def get_tier_features(self, tier: str) -> dict:
        return TIER_FEATURES.get(tier, TIER_FEATURES["free"])


billing_service = BillingService()