"""Conservative Firecrawl credential failures; never inspect scraped content."""

import httpx

# Verified in firecrawl/firecrawl at 7d8e92dc5d270b1247d60e809c3fd32f52e0e47b:
# apps/api/src/controllers/auth.ts and apps/api/src/routes/shared.ts.
# unknown_key/team_banned are internal log reasons, NOT wire error codes.
_AUTH_ERRORS = {
    401: "Unauthorized: Invalid token",
    403: "Unauthorized: This account has been banned. Contact support@firecrawl.com if you believe this is a mistake.",
}


def is_permanent_auth_failure(response: httpx.Response) -> bool:
    expected = _AUTH_ERRORS.get(response.status_code)
    if expected is None or response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return False
    try:
        payload = response.json()
    except (ValueError, UnicodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("success") is False
        and payload.get("error") == expected
    )
