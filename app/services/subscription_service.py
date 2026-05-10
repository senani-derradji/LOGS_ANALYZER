from datetime import datetime
from dateutil.relativedelta import relativedelta
from typing import Optional
from pydantic import BaseModel, Field


class ExpiryCalculationError(Exception):
    """Raised when subscription expiry calculation fails."""


class SubscriptionValidationResult(BaseModel):
    """Result of a subscription validation check."""

    is_active: bool = Field(..., description="Whether the subscription is currently active")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    days_until_expiry: Optional[int] = Field(None, description="Days remaining until expiry (None if no expiry)")
    tier: str = Field(..., description="Subscription tier (free, pro, enterprise)")


class SubscriptionService:
    """Service for subscription expiration logic.

    Handles expiry date calculation and validation with proper edge case
    handling (leap years, varying month lengths) using dateutil.
    """

    TIER_DURATION_MONTHS = {
        "free": None,        # Free tier has no expiration
        "pro": 1,            # 1 month
        "enterprise": 1,     # 1 month
    }

    @classmethod
    def calculate_expiry_date(
        cls,
        activation_date: datetime,
        tier: str = "pro"
    ) -> Optional[datetime]:
        """Calculate subscription expiry date from activation date and tier.

        Args:
            activation_date: The date when subscription becomes active
            tier: Subscription tier (free, pro, enterprise)

        Returns:
            Expiration datetime (1 month from activation for paid tiers,
            None for free tier)

        Raises:
            ExpiryCalculationError: If tier is invalid or calculation fails
        """
        try:
            if tier not in cls.TIER_DURATION_MONTHS:
                raise ExpiryCalculationError(
                    f"Invalid subscription tier: {tier}. "
                    f"Must be one of: {list(cls.TIER_DURATION_MONTHS.keys())}"
                )

            months = cls.TIER_DURATION_MONTHS[tier]
            if months is None:
                return None

            # Use relativedelta for proper month arithmetic
            # Handles leap years, month-end dates correctly:
            # - Jan 31 + 1 month = Feb 28/29 (not March 3)
            # - Feb 28 + 1 month = Mar 28 (consistent day-of-month)
            expiry = activation_date + relativedelta(months=months)

            return expiry

        except Exception as e:
            if isinstance(e, ExpiryCalculationError):
                raise
            raise ExpiryCalculationError(
                f"Failed to calculate expiry date: {str(e)}"
            ) from e

    @classmethod
    def validate_subscription(
        cls,
        tier: str,
        expires_at: Optional[datetime],
        current_time: Optional[datetime] = None
    ) -> SubscriptionValidationResult:
        """Validate if a subscription is currently active.

        Args:
            tier: Subscription tier (free, pro, enterprise)
            expires_at: Expiration timestamp (None for free tier)
            current_time: Time to check against (defaults to now)

        Returns:
            SubscriptionValidationResult with validation details
        """
        if current_time is None:
            current_time = datetime.utcnow()

        # Free tier is always active with no expiry
        if tier == "free":
            return SubscriptionValidationResult(
                is_active=True,
                expires_at=None,
                days_until_expiry=None,
                tier=tier
            )

        # Paid tiers require an expiry date
        if expires_at is None:
            return SubscriptionValidationResult(
                is_active=False,
                expires_at=None,
                days_until_expiry=None,
                tier=tier
            )

        # Check if expired (expires_at is the moment subscription becomes invalid)
        is_active = expires_at > current_time

        days_until_expiry = (expires_at - current_time).days

        return SubscriptionValidationResult(
            is_active=is_active,
            expires_at=expires_at,
            days_until_expiry=days_until_expiry,
            tier=tier
        )

    @classmethod
    def format_expiry_date(
        cls,
        expires_at: Optional[datetime],
        tier: str = "free"
    ) -> str:
        """Format expiration date for display.

        Args:
            expires_at: Expiration timestamp
            tier: Subscription tier

        Returns:
            Formatted string (e.g., "2026-06-06 09:00:00", "N/A", "Lifetime")
        """
        if tier == "free":
            return "Lifetime"

        if expires_at is None:
            return "N/A"

        return expires_at.strftime("%Y-%m-%d %H:%M:%S")
