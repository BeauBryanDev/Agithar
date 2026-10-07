import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.users import TokenData


logger = get_logger("core.auth")

BCRYPT_ROUNDS = 12
BCRYPT_MAX_BYTES = 72
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "agithar"
JWT_AUDIENCE = "agithar-api"
JWT_LEEWAY_SECONDS = 10
ACCESS_TOKEN_TYPE = "access"
REQUIRED_CLAIMS = ("exp", "iat", "nbf", "sub", "jti", "iss", "aud", "typ")

# GUEST tokens (public demo). They share the signing key but nothing else
# with a user's access token: another audience, another type, another
# subject shape and an explicit role. Each of those alone is enough for the
# user routes to refuse a guest token and for the public routes to refuse a
# user token; having all of them keeps the two kinds from ever mixing.
GUEST_AUDIENCE = "agithar-public"
GUEST_TOKEN_TYPE = "guest"
GUEST_ROLE = "guest"
GUEST_SUBJECT = re.compile(r"^guest:[0-9a-f]{32}$")
GUEST_REQUIRED_CLAIMS = REQUIRED_CLAIMS + ("role",)
DUMMY_HASH = bcrypt.hashpw(
    b"dummy-password", bcrypt.gensalt(BCRYPT_ROUNDS)
).decode("utf-8")

bearer_scheme = HTTPBearer(auto_error=False)


class AuthConfigError(Exception):
    pass


class InvalidTokenError(Exception):
    pass


def hash_password(password: str) -> str:
    
    encoded = password.encode("utf-8")

    if len(encoded) > BCRYPT_MAX_BYTES:
        raise ValueError("password is too long")

    salt = bcrypt.gensalt(BCRYPT_ROUNDS)
    return bcrypt.hashpw(encoded, salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    
    encoded = password.encode("utf-8")

    if len(encoded) > BCRYPT_MAX_BYTES:
        return False

    try:
        return bcrypt.checkpw(encoded, password_hash.encode("utf-8"))
    
    except ValueError:
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        cost = int(password_hash.split("$")[2])
        
    except (IndexError, ValueError):
        return True

    return cost < BCRYPT_ROUNDS


def get_signing_key() -> str:
    secret = get_settings().jwt_secret_key

    if secret is None:
        logger.error("jwt secret key is not configured")
        raise AuthConfigError("jwt secret key is not configured")

    return secret.get_secret_value()


def create_access_token(user_id: int) -> str:
    
    now = datetime.now(timezone.utc)
    ttl = timedelta(seconds=get_settings().access_token_ttl_seconds)

    claims = {
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(16),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "typ": ACCESS_TOKEN_TYPE,
    }

    return jwt.encode(claims, get_signing_key(), 
                      algorithm=JWT_ALGORITHM)


def parse_user_id(subject: object) -> int:
    
    if not isinstance(subject, str) or not subject.isascii():
        raise InvalidTokenError("invalid subject")

    if not subject.isdigit():
        raise InvalidTokenError("invalid subject")

    return int(subject)


def decode_access_token(token: str) -> TokenData:
    key = get_signing_key()

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"leeway": JWT_LEEWAY_SECONDS},
        )
        
    except JWTError:
        raise InvalidTokenError("invalid token")

    for claim in REQUIRED_CLAIMS:
        if claim not in claims:
            raise InvalidTokenError("missing claim")

    if claims.get("typ") != ACCESS_TOKEN_TYPE:
        raise InvalidTokenError("wrong token type")

    return TokenData(user_id=parse_user_id(claims.get("sub")))


@dataclass(frozen=True)
class GuestClaims:
    subject: str
    role: str
    expires_at: int


def create_guest_token() -> tuple[str, int]:
    # No password and no database: anyone may ask. The token only says "a
    # visitor of the public demo, for a while"; it opens nothing but the
    # public chat. Returns the token and its lifetime in seconds.
    now = datetime.now(timezone.utc)
    seconds = get_settings().guest_token_ttl_seconds

    claims = {
        "sub": f"guest:{uuid.uuid4().hex}",
        "role": GUEST_ROLE,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=seconds),
        "jti": secrets.token_urlsafe(16),
        "iss": JWT_ISSUER,
        "aud": GUEST_AUDIENCE,
        "typ": GUEST_TOKEN_TYPE,
    }

    return jwt.encode(claims, get_signing_key(), algorithm=JWT_ALGORITHM), seconds


def decode_guest_token(token: str) -> GuestClaims:
    key = get_signing_key()

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[JWT_ALGORITHM],
            audience=GUEST_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"leeway": JWT_LEEWAY_SECONDS},
        )

    except JWTError:
        raise InvalidTokenError("invalid token")

    for claim in GUEST_REQUIRED_CLAIMS:
        if claim not in claims:
            raise InvalidTokenError("missing claim")

    if claims["typ"] != GUEST_TOKEN_TYPE or claims["role"] != GUEST_ROLE:
        raise InvalidTokenError("wrong token type")

    subject = claims["sub"]

    if not isinstance(subject, str) or not GUEST_SUBJECT.match(subject):
        raise InvalidTokenError("invalid subject")

    return GuestClaims(subject, GUEST_ROLE, int(claims["exp"]))


def unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_token_data(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        bearer_scheme
    ),
) -> TokenData:
    if credentials is None:
        raise unauthorized()

    try:
        return decode_access_token(credentials.credentials)
    
    except InvalidTokenError:
        raise unauthorized()
    
    except AuthConfigError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is unavailable",
        )
