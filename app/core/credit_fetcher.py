from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.exceptions import InvalidTag
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.core.security import decrypt_api_key
from app.core.upstream_auth import is_permanent_auth_failure
from app.db.models import ApiKey, CreditSnapshot
from app.errors import FcamError

logger = logging.getLogger(__name__)


def _parse_datetime(dt_str: str | None) -> datetime | None:
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None


async def fetch_credit_from_firecrawl(
    *,
    db: Session,
    key: ApiKey,
    master_key: bytes,
    config: AppConfig,
    request_id: str,
) -> CreditSnapshot:
    """
    调用 Firecrawl `GET /v2/team/credit-usage` 获取真实额度，并写入快照。

    设计点：
    - 成功与失败都写入 credit_snapshots（失败 fetch_success=False）
    - 成功时同步更新 ApiKey 的缓存字段（cached_* / last_credit_* / next_refresh_at）
    - 失败时尽量不影响系统主流程（由调用方决定是否吞掉异常）
    """
    # 1) 解密上游 API Key
    try:
        plaintext_api_key = decrypt_api_key(master_key, key.api_key_ciphertext)
    except (InvalidTag, ValueError) as exc:
        key.status = "decrypt_failed"
        key.is_active = False
        snapshot = CreditSnapshot(
            api_key_id=key.id,
            remaining_credits=0,
            plan_credits=0,
            fetch_success=False,
            error_message=f"Decryption failed: {exc}",
        )
        try:
            db.add(snapshot)
            db.commit()
        except Exception:
            db.rollback()
        raise FcamError(status_code=500, code="DECRYPTION_FAILED", message="Failed to decrypt API key") from exc

    url = f"{config.firecrawl.base_url}/v2/team/credit-usage"
    headers = {
        "Authorization": f"Bearer {plaintext_api_key}",
        "X-Request-Id": request_id,
        "Accept": "application/json",
    }
    timeout = httpx.Timeout(max(int(config.firecrawl.timeout), 1))

    now = datetime.now(timezone.utc)

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.get(url, headers=headers)
    except httpx.TimeoutException as exc:
        snapshot = CreditSnapshot(
            api_key_id=key.id,
            remaining_credits=0,
            plan_credits=0,
            fetch_success=False,
            error_message="Request timeout",
        )
        try:
            db.add(snapshot)
            db.commit()
        except Exception:
            db.rollback()
        raise FcamError(status_code=504, code="TIMEOUT", message="Firecrawl API request timeout") from exc

    # 2) 处理响应
    if response.status_code == 200:
        try:
            payload = response.json()
            if asyncio.iscoroutine(payload):
                payload = await payload
        except Exception as exc:
            snapshot = CreditSnapshot(
                api_key_id=key.id,
                remaining_credits=0,
                plan_credits=0,
                fetch_success=False,
                error_message="Invalid JSON response",
            )
            try:
                db.add(snapshot)
                db.commit()
            except Exception:
                db.rollback()
            raise FcamError(status_code=502, code="UPSTREAM_ERROR", message="Invalid upstream JSON") from exc

        data = payload.get("data") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or payload.get("success") is not True
            or not isinstance(data, dict)
            or any(type(data.get(field)) is not int or data[field] < 0
                   for field in ("remainingCredits", "planCredits"))
        ):
            snapshot = CreditSnapshot(
                api_key_id=key.id,
                remaining_credits=0,
                plan_credits=0,
                fetch_success=False,
                error_message="Invalid credit usage response",
            )
            try:
                db.add(snapshot)
                db.commit()
            except Exception:
                db.rollback()
            raise FcamError(status_code=502, code="UPSTREAM_ERROR", message="Firecrawl credit usage failed")

        remaining = data["remainingCredits"]
        plan = data["planCredits"]

        snapshot = CreditSnapshot(
            api_key_id=key.id,
            remaining_credits=remaining,
            plan_credits=plan,
            billing_period_start=_parse_datetime(data.get("billingPeriodStart")),
            billing_period_end=_parse_datetime(data.get("billingPeriodEnd")),
            fetch_success=True,
        )

        try:
            db.add(snapshot)
            db.flush()

            key.cached_remaining_credits = remaining
            key.cached_plan_credits = plan
            key.last_credit_snapshot_id = snapshot.id
            key.last_credit_check_at = now

            # 计算下次刷新时间（避免循环 import）
            try:
                from app.core.credit_refresh import calculate_next_refresh_time

                key.next_refresh_at = calculate_next_refresh_time(key, config)
            except Exception:
                key.next_refresh_at = None

            db.commit()
            db.refresh(snapshot)
            return snapshot
        except Exception as exc:
            db.rollback()
            logger.exception(
                "credit.snapshot_write_failed",
                extra={"fields": {"api_key_id": key.id, "request_id": request_id}},
            )
            raise FcamError(status_code=503, code="DB_UNAVAILABLE", message="Database unavailable") from exc

    if response.status_code in {401, 403}:
        permanent = is_permanent_auth_failure(response)
        if permanent:
            key.status = "failed"
            key.is_active = False
        elif key.is_active and key.status != "disabled":
            key.status = "cooling"
            key.cooldown_until = now + timedelta(seconds=max(config.firecrawl.failed_cooldown_seconds, 1))
        snapshot = CreditSnapshot(
            api_key_id=key.id,
            remaining_credits=0,
            plan_credits=0,
            fetch_success=False,
            error_message=f"{response.status_code} {getattr(response, 'text', '')}",
        )
        try:
            db.add(snapshot)
            db.commit()
        except Exception:
            db.rollback()
        raise FcamError(
            status_code=int(response.status_code),
            code="INVALID_API_KEY" if permanent else "UPSTREAM_ERROR",
            message="API key is invalid or unauthorized" if permanent else "Unconfirmed upstream authentication failure",
        )

    if response.status_code == 429:
        key.status = "cooling"
        key.cooldown_until = now
        snapshot = CreditSnapshot(
            api_key_id=key.id,
            remaining_credits=0,
            plan_credits=0,
            fetch_success=False,
            error_message="429 Rate Limited",
        )
        try:
            db.add(snapshot)
            db.commit()
        except Exception:
            db.rollback()
        raise FcamError(status_code=429, code="RATE_LIMITED", message="Firecrawl API rate limited")

    snapshot = CreditSnapshot(
        api_key_id=key.id,
        remaining_credits=0,
        plan_credits=0,
        fetch_success=False,
        error_message=f"{response.status_code} {getattr(response, 'text', '')}",
    )
    try:
        db.add(snapshot)
        db.commit()
    except Exception:
        db.rollback()

    raise FcamError(
        status_code=int(response.status_code),
        code="UPSTREAM_ERROR",
        message=f"Firecrawl API error: {response.status_code}",
    )
