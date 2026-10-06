
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


EMAIL_PATTERN = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
USERNAME_PATTERN = r"^[A-Za-z0-9_.-]{3,32}$"
PHONE_PATTERN = r"^\+?[0-9]{7,15}$"
GENDERS = Literal["male", "female", "other"]
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 72
PASSWORD_MAX_BYTES = 72


def check_password_bytes(value: str) -> str:
    if len(value.encode("utf-8")) > PASSWORD_MAX_BYTES:
        raise ValueError("password is too long")

    return value


def check_dob_not_in_future(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return value

    if value > datetime.now(value.tzinfo):
        raise ValueError("dob cannot be in the future")

    return value


class UserBase(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    username: str = Field(pattern=USERNAME_PATTERN)
    email: str = Field(max_length=254, pattern=EMAIL_PATTERN)
    phone_number: Optional[str] = Field(default=None, pattern=PHONE_PATTERN)
    address: Optional[str] = Field(default=None, max_length=255)
    country: Optional[str] = Field(default=None, max_length=100)
    city: Optional[str] = Field(default=None, max_length=100)
    gender: Optional[GENDERS] = None
    dob: Optional[datetime] = None

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()

        return value

    @field_validator("dob")
    @classmethod
    def validate_dob(cls, value: Optional[datetime]) -> Optional[datetime]:
        return check_dob_not_in_future(value)


class UserCreate(UserBase):
    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, 
        max_length=PASSWORD_MAX_LENGTH
    )

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return check_password_bytes(value)

    def __repr__(self) -> str:
        return f"UserCreate(username={self.username!r})"


class AdminUserCreate(UserCreate):
    # Only the admin-only create route accepts this: the role is decided by
    # the admin who creates the account, never by the new user.
    is_admin: bool = False


class UserUpdate(BaseModel):
    phone_number: Optional[str] = Field(default=None, pattern=PHONE_PATTERN)
    address: Optional[str] = Field(default=None, max_length=255)
    country: Optional[str] = Field(default=None, max_length=100)
    city: Optional[str] = Field(default=None, max_length=100)

    model_config = ConfigDict(extra="forbid")


class UserAdminUpdate(BaseModel):
    is_active: bool

    model_config = ConfigDict(extra="forbid")


class UserRead(UserBase):
    user_id: int
    is_active: bool
    is_admin: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserList(BaseModel):
    items: list[UserRead]
    total: int = Field(ge=0)
    skip: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)


class UserLogin(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, 
                          max_length=PASSWORD_MAX_LENGTH)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return check_password_bytes(value)

    def __repr__(self) -> str:
        return f"UserLogin(username={self.username!r})"


class PasswordChange(BaseModel):
    current_password: str = Field(
        min_length=1, max_length=PASSWORD_MAX_LENGTH
    )
    new_password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, 
        max_length=PASSWORD_MAX_LENGTH
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("current_password", "new_password")
    @classmethod
    def validate_passwords(cls, value: str) -> str:
        return check_password_bytes(value)

    def __repr__(self) -> str:
        return "PasswordChange()"


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

    def __repr__(self) -> str:
        return f"Token(token_type={self.token_type!r})"


class TokenData(BaseModel):
    user_id: Optional[int] = None
    username: Optional[str] = None
