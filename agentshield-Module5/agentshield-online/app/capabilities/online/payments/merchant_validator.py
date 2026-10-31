"""
Merchant validator — validates merchants against approved registry.
Agents cannot use arbitrary merchant IDs.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.core.exceptions import UnauthorizedMerchantError

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = Path(__file__).parents[5] / "configs" / "payment_policy.yaml"


@dataclass
class MerchantRecord:
    id: str
    name: str
    status: str    # active | blocked | suspended
    domain: str | None = None


class MerchantValidator:
    """
    Validates merchant IDs against the approved merchant registry.
    Merchants must be explicitly registered and active.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        self._merchants: dict[str, MerchantRecord] = {}
        self._approved_ids: set[str] = set()
        self._blocked_ids: set[str] = set()
        path = Path(config_path or _DEFAULT_CONFIG_PATH)
        self._load(path)

    def _load(self, path: Path) -> None:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            payments_cfg = data.get("payments", {})
            self._approved_ids = set(payments_cfg.get("approved_merchants", []))
            self._blocked_ids = set(payments_cfg.get("blocked_merchants", []))

            for raw in data.get("merchants", []):
                rec = MerchantRecord(
                    id=raw["id"],
                    name=raw.get("name", raw["id"]),
                    status=raw.get("status", "active"),
                    domain=raw.get("domain"),
                )
                self._merchants[rec.id] = rec
            logger.info("MerchantValidator: loaded %d merchants", len(self._merchants))
        except Exception as e:
            logger.warning("MerchantValidator: could not load %s: %s", path, e)

    def validate(self, merchant_id: str) -> MerchantRecord:
        """
        Validate a merchant ID.
        Raises UnauthorizedMerchantError if invalid or blocked.
        Returns MerchantRecord if valid.
        """
        if merchant_id in self._blocked_ids:
            raise UnauthorizedMerchantError(
                f"Merchant '{merchant_id}' is blocked"
            )

        if self._approved_ids and merchant_id not in self._approved_ids:
            raise UnauthorizedMerchantError(
                f"Merchant '{merchant_id}' is not in the approved merchant list. "
                "Only registered merchants are permitted."
            )

        record = self._merchants.get(merchant_id)
        if not record:
            raise UnauthorizedMerchantError(
                f"Merchant '{merchant_id}' is not registered"
            )

        if record.status != "active":
            raise UnauthorizedMerchantError(
                f"Merchant '{merchant_id}' is not active (status: {record.status})"
            )

        return record

    def is_valid(self, merchant_id: str) -> bool:
        try:
            self.validate(merchant_id)
            return True
        except UnauthorizedMerchantError:
            return False
