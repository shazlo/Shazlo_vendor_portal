import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from identity_api.app import create_app
from identity_api.core.settings import Settings
from identity_api.services.keys import KeyRing, load_keyring
from identity_api.services.tokens import TokenIssuer

ISSUER = "https://identity.test"
ADMIN_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
# PyJWT checks `iat` and `exp` against the real clock, so the fake clock starts at the real now.
NOW = datetime.now(UTC).replace(microsecond=0)
Configure = Callable[..., Settings]
PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


@pytest.fixture
def configured(settings: Settings, override: Callable[..., Settings]) -> Configure:
    def apply(key_pems: dict[str, str], signing: str, **extra: object) -> Settings:
        return override(
            settings,
            jwt_issuer=ISSUER,
            jwt_keys=json.dumps(key_pems),
            jwt_signing_kid=signing,
            **extra,
        )

    return apply


def make_issuer(settings: Settings, ring: KeyRing, now: datetime = NOW) -> TokenIssuer:
    return TokenIssuer(settings, ring, clock=lambda: now)


def verify(token: str, jwks: dict[str, Any], audience: str = "vendor-api") -> dict[str, Any]:
    """Verifies like a consuming service: key chosen by `kid` from the JWKS, RS256 only."""
    kid = jwt.get_unverified_header(token)["kid"]
    key = jwt.PyJWKSet.from_dict(jwks)[kid]
    return jwt.decode(
        token,
        key.key,
        algorithms=["RS256"],
        audience=audience,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "iss", "sub", "aud", "jti", "roles"]},
        leeway=0,
    )


def test_token_claims_and_header(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1")
    ring = load_keyring(settings)
    issued = make_issuer(settings, ring).issue(
        subject=ADMIN_ID, roles=["vendor_reviewer"], audience="vendor-api"
    )

    header = jwt.get_unverified_header(issued.token)
    assert header == {"alg": "RS256", "typ": "JWT", "kid": "test-key-1"}

    claims = verify(issued.token, ring.jwks())
    assert claims == {
        "iss": ISSUER,
        "sub": str(ADMIN_ID),
        "aud": "vendor-api",
        "roles": ["vendor_reviewer"],
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=15)).timestamp()),
        "jti": issued.jti,
    }
    assert issued.expires_at == NOW + timedelta(minutes=15)


def test_token_carries_no_personal_data(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1")
    ring = load_keyring(settings)
    token = make_issuer(settings, ring).issue(
        subject=ADMIN_ID, roles=["super_admin"], audience="identity-api"
    )
    claims = jwt.decode(token.token, options={"verify_signature": False})
    assert not {"email", "name", "display_name"} & claims.keys()


def test_jti_is_unique(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1")
    issuer = make_issuer(settings, load_keyring(settings))
    ids = {issuer.issue(subject=ADMIN_ID, roles=[], audience="a").jti for _ in range(20)}
    assert len(ids) == 20


def test_audience_is_required(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1")
    with pytest.raises(ValueError, match="audience"):
        make_issuer(settings, load_keyring(settings)).issue(subject=ADMIN_ID, roles=[], audience="")


def test_expiry_follows_the_setting(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1", access_token_ttl_seconds=60)
    ring = load_keyring(settings)
    issued = make_issuer(settings, ring).issue(subject=ADMIN_ID, roles=[], audience="a")
    claims = jwt.decode(issued.token, options={"verify_signature": False})
    assert claims["exp"] - claims["iat"] == 60


def test_expired_token_is_rejected(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1")
    ring = load_keyring(settings)
    old = NOW - timedelta(minutes=16)
    issued = make_issuer(settings, ring, now=old).issue(
        subject=ADMIN_ID, roles=[], audience="vendor-api"
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        verify(issued.token, ring.jwks())


def test_wrong_audience_is_rejected(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1")
    ring = load_keyring(settings)
    issued = make_issuer(settings, ring).issue(subject=ADMIN_ID, roles=[], audience="vendor-api")
    with pytest.raises(jwt.InvalidAudienceError):
        verify(issued.token, ring.jwks(), audience="identity-api")


def test_kid_selects_the_signing_key(configured: Configure, key_pems: dict[str, str]) -> None:
    for kid in ("test-key-1", "test-key-2"):
        configured_settings = configured(key_pems, kid)
        ring = load_keyring(configured_settings)
        issued = make_issuer(configured_settings, ring).issue(
            subject=ADMIN_ID, roles=[], audience="vendor-api"
        )
        assert jwt.get_unverified_header(issued.token)["kid"] == kid
        verify(issued.token, ring.jwks())


def test_token_does_not_verify_against_the_other_key(
    configured: Configure, key_pems: dict[str, str]
) -> None:
    """The `kid` matters: a token must verify against its own key and not another."""
    settings = configured(key_pems, "test-key-1")
    ring = load_keyring(settings)
    token = make_issuer(settings, ring).issue(subject=ADMIN_ID, roles=[], audience="vendor-api")
    other = jwt.PyJWKSet.from_dict(ring.jwks())["test-key-2"]
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token.token, other.key, algorithms=["RS256"], audience="vendor-api")


def test_rotation_overlap(configured: Configure, key_pems: dict[str, str]) -> None:
    """Step 1: new key published, old still signs. Step 2: new key signs, old still published."""
    old_only = {"test-key-1": key_pems["test-key-1"]}
    before = configured(old_only, "test-key-1")
    before_ring = load_keyring(before)
    old_token = make_issuer(before, before_ring).issue(
        subject=ADMIN_ID, roles=[], audience="vendor-api"
    )

    published = configured(key_pems, "test-key-1")
    published_ring = load_keyring(published)
    assert set(published_ring.kids) == {"test-key-1", "test-key-2"}
    assert (
        jwt.get_unverified_header(
            make_issuer(published, published_ring)
            .issue(subject=ADMIN_ID, roles=[], audience="vendor-api")
            .token
        )["kid"]
        == "test-key-1"
    )

    switched = configured(key_pems, "test-key-2")
    switched_ring = load_keyring(switched)
    new_token = make_issuer(switched, switched_ring).issue(
        subject=ADMIN_ID, roles=[], audience="vendor-api"
    )
    assert jwt.get_unverified_header(new_token.token)["kid"] == "test-key-2"

    # With both keys published, tokens signed by either verify.
    jwks = switched_ring.jwks()
    verify(old_token.token, jwks)
    verify(new_token.token, jwks)


def test_jwks_has_public_material_only(configured: Configure, key_pems: dict[str, str]) -> None:
    ring = load_keyring(configured(key_pems, "test-key-1"))
    keys = ring.jwks()["keys"]
    assert [key["kid"] for key in keys] == ["test-key-1", "test-key-2"]
    for key in keys:
        assert set(key) - {"key_ops"} == {"kty", "n", "e", "kid", "use", "alg"}
        assert not PRIVATE_PARAMS & key.keys()
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"


def test_jwks_endpoint(configured: Configure, key_pems: dict[str, str]) -> None:
    settings = configured(key_pems, "test-key-1")
    with TestClient(create_app(settings, readiness_checks={})) as client:
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "max-age=600"
        assert response.headers["content-type"] == "application/json"
        body = response.json()
        assert {key["kid"] for key in body["keys"]} == {"test-key-1", "test-key-2"}
        for pem in key_pems.values():
            assert "PRIVATE" not in response.text
            assert pem not in response.text
        for key in body["keys"]:
            assert not PRIVATE_PARAMS & key.keys()

        # End to end: a token from the app's issuer verifies against what the endpoint served.
        issued = client.app.state.token_issuer.issue(  # type: ignore[attr-defined]
            subject=ADMIN_ID, roles=["vendor_reviewer"], audience="vendor-api"
        )
        claims = jwt.decode(
            issued.token,
            jwt.PyJWKSet.from_dict(body)["test-key-1"].key,
            algorithms=["RS256"],
            audience="vendor-api",
            issuer=ISSUER,
        )
        assert claims["roles"] == ["vendor_reviewer"]


def test_app_refuses_to_start_without_keys(settings: Settings) -> None:
    from identity_api.services.keys import KeyConfigError

    with pytest.raises(KeyConfigError):
        create_app(settings.model_copy(update={"jwt_keys": None}), readiness_checks={})
