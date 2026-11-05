"""Offline regression tests: real handlers and SQLite, only mocked HTTP."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import Secrets
from app.core.concurrency import ConcurrencyManager
from app.core.credit_fetcher import fetch_credit_from_firecrawl
from app.core.forwarder import Forwarder
from app.core.key_pool import KeyPool
from app.core.security import derive_master_key_bytes
from app.errors import FcamError
from tests.integration.test_forwarder import _add_client, _add_key, _setup_db

INVALID = "Unauthorized: Invalid token"
BANNED = "Unauthorized: This account has been banned. Contact support@firecrawl.com if you believe this is a mistake."
CASES = [
    (401, {"success": False, "error": INVALID}, True),
    (403, {"success": False, "error": BANNED}, True),
    (403, "<html>Forbidden</html>", False),
    (401, {"error": INVALID}, False),
    (403, {"success": False, "error": INVALID}, False),
    (401, {"success": False, "error": BANNED}, False),
    (403, {"success": True, "error": BANNED}, False),
    (401, {"success": 0, "error": INVALID}, False),
    (401, {"success": False, "error": {"message": INVALID}}, False),
    (403, {"success": False, "code": "team_banned"}, False),
    (401, {"success": False, "code": "unknown_key"}, False),
    (403, {"success": False, "error": "credits exceeded", "data": {"text": BANNED}}, False),
    (403, [], False),
]


def response(status, body):
    if isinstance(body, str):
        return httpx.Response(status, text=body, headers={"content-type": "text/html"})
    return httpx.Response(status, json=body)


@pytest.mark.parametrize("mode", ["forward", "pinned", "test"])
@pytest.mark.parametrize("status,body,disabled", CASES)
def test_auth_response_safety(tmp_path, mode, status, body, disabled):
    config, db = _setup_db(tmp_path)
    config.firecrawl.max_retries = 0
    secrets = Secrets(admin_token="admin", master_key="master")
    client, _ = _add_client(db, secrets.master_key)
    key = _add_key(db, secrets.master_key, "fc-fake-test", "hash", "test", client_id=client.id)
    fwd = Forwarder(config=config, secrets=secrets, key_pool=KeyPool(),
                    key_concurrency=ConcurrencyManager(),
                    transport=httpx.MockTransport(lambda req: response(status, body)))
    if mode == "test":
        result = fwd.test_key(db=db, request_id="offline-test", key=key)
        assert not result.ok
    else:
        result = fwd.forward(db=db, request_id="offline-test", client=client, method="GET",
                             upstream_path="/crawl/fake", json_body=None, inbound_headers={},
                             pinned_api_key_id=key.id if mode == "pinned" else None)
    assert result.upstream_status_code == status
    db.expire_all()
    assert key.is_active is not disabled
    assert key.status == ("disabled" if disabled else "cooling")
    if not disabled:
        assert key.cooldown_until is not None
        if mode == "pinned":
            with pytest.raises(FcamError) as exc:
                fwd.forward(db=db, request_id="offline-repeat", client=client, method="GET",
                            upstream_path="/crawl/fake", json_body=None, inbound_headers={},
                            pinned_api_key_id=key.id)
            assert exc.value.code == "ALL_KEYS_COOLING"
    db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body,disabled", CASES + [
    (200, {"success": True, "data": {}}, False),
    (200, {"success": True, "data": {"remainingCredits": None, "planCredits": 100}}, False),
    (200, {"success": True, "data": {"remainingCredits": True, "planCredits": 100}}, False),
    (200, {"success": True, "data": {"remainingCredits": "garbage", "planCredits": 100}}, False),
    (200, {"success": False, "error": "credits exceeded"}, False),
    (200, [], False),
])
async def test_credit_failure_preserves_balance(tmp_path, monkeypatch, status, body, disabled):
    config, db = _setup_db(tmp_path)
    key = _add_key(db, "master", "fc-fake-test", "hash", "test")
    key.cached_remaining_credits = 100
    key.cached_plan_credits = 500
    db.commit()
    real_client = httpx.AsyncClient
    monkeypatch.setattr("app.core.credit_fetcher.httpx.AsyncClient", lambda **kw: real_client(
        **kw, transport=httpx.MockTransport(lambda req: response(status, body))))
    with pytest.raises(FcamError) as exc:
        await fetch_credit_from_firecrawl(db=db, key=key, master_key=derive_master_key_bytes("master"),
                                         config=config, request_id="offline-test")
    db.expire_all()
    assert key.is_active is not disabled
    assert key.cached_remaining_credits == 100
    assert key.cached_plan_credits == 500
    assert exc.value.code == ("INVALID_API_KEY" if disabled else "UPSTREAM_ERROR")
    if status in {401, 403} and not disabled:
        assert key.status == "cooling" and key.cooldown_until is not None
    db.close()


def test_pool_recovers_after_gateway_incident(tmp_path):
    config, db = _setup_db(tmp_path)
    config.firecrawl.max_retries = 1
    secrets = Secrets(admin_token="admin", master_key="master")
    client, _ = _add_client(db, secrets.master_key)
    keys = [_add_key(db, secrets.master_key, f"fc-fake-{n}", f"hash{n}", "test", client_id=client.id) for n in range(2)]
    incident = True
    fwd = Forwarder(config=config, secrets=secrets, key_pool=KeyPool(),
                    key_concurrency=ConcurrencyManager(), transport=httpx.MockTransport(
                        lambda req: response(403, "<html>Forbidden</html>") if incident else response(200, {"success": True})))
    args = dict(db=db, request_id="offline-test", client=client, method="GET",
                upstream_path="/crawl/fake", json_body=None, inbound_headers={})
    assert fwd.forward(**args).upstream_status_code == 403
    for key in keys:
        db.refresh(key)
        assert key.is_active and key.status == "cooling"
        key.cooldown_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    incident = False
    assert fwd.forward(**args).upstream_status_code == 200
    assert all(key.is_active for key in keys)
    db.close()
