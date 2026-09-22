from fastapi import APIRouter, HTTPException, Request, Response, status

from apps.api.core.config import get_settings
from apps.api.core.deps import CurrentUserDep, DbDep
from apps.api.modules.auth import service
from apps.api.modules.auth.schemas import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MfaDisableRequest,
    MfaEnableResponse,
    MfaLoginRequest,
    MfaRecoveryCodesResponse,
    MfaVerifyEnableRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# --- F-08: refresh token travels as an HttpOnly cookie, never in the JSON body --------------
# It used to be returned in the response body and stored in localStorage, where any XSS could
# read it and mint access tokens for its whole 7-day life. The token itself and the rotation /
# reuse-detection machinery (F-04) are unchanged -- only the TRANSPORT moved. The short-lived
# access token still comes back in the body, because the SPA holds it in memory only and sends
# it as a bearer header; that is what keeps the API stateless.


def _strip_refresh_from_body(tokens: TokenResponse, request: Request) -> TokenResponse:
    """F-08: do not echo the refresh token back to a BROWSER.

    Setting the HttpOnly cookie is pointless if the same secret is also sitting in the JSON
    body, where script can read it straight off the login response -- exactly the exposure
    this finding is about. Browsers are identified by having sent an Origin/Referer; they get
    the cookie and an empty body field. Non-browser clients (CLI, integration tests,
    service-to-service) send neither header and still receive the token, because they have no
    cookie jar and would otherwise be unable to refresh at all."""
    if request.headers.get("origin") or request.headers.get("referer"):
        return tokens.model_copy(update={"refresh_token": None})
    return tokens


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Attach the rotated refresh token as an HttpOnly cookie.

    httponly  -- JavaScript cannot read it; this is the whole point of F-08.
    samesite  -- 'strict' by default: /auth/refresh and /auth/logout are cookie-authenticated,
                 and a strict cookie is never attached to a cross-site request, so a third-party
                 page cannot drive them. That IS the CSRF control (see _require_same_origin for
                 the defence-in-depth check that backs it up).
    secure    -- forced true in production by validate_production(); left configurable so plain
                 http local development still works.
    path      -- scoped to the auth routes, so the cookie is not attached to (or loggable by)
                 ordinary API calls.
    max_age   -- matches the refresh token's own lifetime, so the browser drops it when the
                 server-side row would have expired anyway.
    """
    s = get_settings()
    response.set_cookie(
        key=s.refresh_cookie_name,
        value=refresh_token,
        httponly=True,
        secure=s.refresh_cookie_secure,
        samesite=s.refresh_cookie_samesite,
        path=s.refresh_cookie_path,
        max_age=s.jwt_refresh_token_ttl_days * 24 * 60 * 60,
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Expire the cookie with the SAME attributes it was set with -- a delete_cookie whose
    path/samesite differ leaves the original cookie in place, which would keep a revoked-but-
    still-present credential in the browser."""
    s = get_settings()
    response.delete_cookie(
        key=s.refresh_cookie_name,
        path=s.refresh_cookie_path,
        httponly=True,
        secure=s.refresh_cookie_secure,
        samesite=s.refresh_cookie_samesite,
    )


def _refresh_from(request: Request, payload: RefreshRequest | LogoutRequest | None) -> str:
    """The refresh token for this request: an EXPLICIT body token wins, cookie otherwise.

    ORDER MATTERS AND IS SECURITY-RELEVANT. Preferring the cookie would silently ignore a
    caller that named a specific token -- so replaying an OLD token while holding a fresh
    cookie would rotate the fresh one and return 200, defeating F-04's reuse detection
    (observed exactly that before this ordering was fixed). Honouring the explicit token means
    a replayed one is evaluated on its own merits and correctly trips reuse detection.

    The body path exists for non-browser clients (CLI, integration tests, service-to-service)
    that have no cookie jar. A browser sends no body at all, so the SPA never handles the
    token -- which is what removes it from JS reach."""
    if payload is not None and getattr(payload, "refresh_token", None):
        return payload.refresh_token
    cookie = request.cookies.get(get_settings().refresh_cookie_name)
    if cookie:
        return cookie
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing refresh token")


def _require_same_origin(request: Request) -> None:
    """Defence in depth behind SameSite=strict for the cookie-authenticated routes.

    SameSite already stops a cross-site browser request from carrying the cookie. This adds an
    explicit Origin/Referer check so the protection does not rest on one browser behaviour
    alone (older browsers, or a future relaxation of the cookie policy). Requests with NO
    Origin/Referer are allowed through: non-browser clients (curl, the CLI, the test suite)
    legitimately omit both, and they authenticate by body token rather than by cookie."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return
    allowed = set(get_settings().cors_allow_origins)
    from urllib.parse import urlsplit

    parts = urlsplit(origin)
    normalized = f"{parts.scheme}://{parts.netloc}"
    if "*" in allowed or normalized in allowed:
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Cross-origin refresh is not allowed")


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: DbDep, request: Request, response: Response) -> TokenResponse:
    user = await service.register_user(db, payload.email, payload.password, payload.full_name)
    tokens = await service.issue_token_pair(db, user)
    _set_refresh_cookie(response, tokens.refresh_token)   # F-08
    return _strip_refresh_from_body(tokens, request)


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: DbDep, request: Request, response: Response) -> LoginResponse:
    # Backward compatible: no-MFA users still get access_token/refresh_token here; MFA users get
    # mfa_required + a challenge token to finish at /auth/mfa/login.
    result = await service.begin_login(db, payload.email, payload.password)
    # F-08: only a completed login (no second factor pending) carries a refresh token.
    if result.refresh_token:
        _set_refresh_cookie(response, result.refresh_token)
        if request.headers.get("origin") or request.headers.get("referer"):
            result = result.model_copy(update={"refresh_token": None})
    return result


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, db: DbDep, response: Response, payload: RefreshRequest | None = None) -> TokenResponse:
    # F-08: cookie-first. The body form stays for non-browser clients; `payload` is optional so
    # a browser can POST an empty body and authenticate purely by cookie.
    _require_same_origin(request)
    tokens = await service.rotate_refresh_token(db, _refresh_from(request, payload))
    _set_refresh_cookie(response, tokens.refresh_token)   # rotation -> new cookie (F-04 chain)
    return _strip_refresh_from_body(tokens, request)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, db: DbDep, response: Response, payload: LogoutRequest | None = None) -> None:
    # F-08: revoke server-side AND clear the cookie. The cookie is cleared unconditionally --
    # even if the token was already revoked or absent -- so logout can never leave a usable
    # credential sitting in the browser.
    _require_same_origin(request)
    token = (
        payload.refresh_token if payload is not None and payload.refresh_token else None
    ) or request.cookies.get(get_settings().refresh_cookie_name)
    if token:
        await service.revoke_refresh_token(db, token)
    _clear_refresh_cookie(response)


# --- MFA management (authenticated) --------------------------------------------------------

@router.post("/mfa/enable", response_model=MfaEnableResponse)
async def mfa_enable(db: DbDep, current_user: CurrentUserDep) -> MfaEnableResponse:
    """Begin enrollment: returns the provisioning URI (+ secret for manual entry). MFA is NOT
    enabled until /auth/mfa/verify-enable confirms a code."""
    return await service.start_mfa_enrollment(db, current_user)


@router.post("/mfa/verify-enable", response_model=MfaRecoveryCodesResponse)
async def mfa_verify_enable(
    payload: MfaVerifyEnableRequest, db: DbDep, current_user: CurrentUserDep
) -> MfaRecoveryCodesResponse:
    """Confirm the first code, enable MFA, and return one-time recovery codes (shown once)."""
    return await service.verify_and_enable_mfa(db, current_user, payload.code)


@router.post("/mfa/login", response_model=TokenResponse)
async def mfa_login(payload: MfaLoginRequest, db: DbDep, request: Request, response: Response) -> TokenResponse:
    """Complete a login that required MFA: exchange the mfa challenge token + code for tokens."""
    tokens = await service.complete_mfa_login(db, payload.mfa_token, payload.code)
    _set_refresh_cookie(response, tokens.refresh_token)   # F-08
    return _strip_refresh_from_body(tokens, request)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(payload: MfaDisableRequest, db: DbDep, current_user: CurrentUserDep) -> None:
    """Disable MFA (requires password + a current TOTP or recovery code)."""
    await service.disable_mfa(db, current_user, payload.password, payload.code)
