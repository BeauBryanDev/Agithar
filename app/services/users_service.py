from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import DUMMY_HASH, hash_password, verify_password
from app.core.logging import get_logger
from app.db.postgresql.users import User
from app.schemas.users import (
    PasswordChange,
    UserAdminUpdate,
    UserCreate,
    UserUpdate,
)


logger = get_logger("services.users")


class UserNotFoundError(Exception):
    pass


class UserAlreadyExistsError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class LastAdminError(Exception):
    pass


def commit_or_rollback(db: Session) -> None:
    try:
        db.commit()
        
    except IntegrityError:
        db.rollback()
        raise UserAlreadyExistsError("username or email already in use")
    
    except Exception:
        db.rollback()
        raise


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.get(User, user_id)


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    statement = select(User).where(User.username == username)
    return db.scalars(statement).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    statement = select(User).where(User.email == email.strip().lower())
    return db.scalars(statement).first()


def get_user_or_raise(db: Session, user_id: int) -> User:
    user = get_user_by_id(db, user_id)
    if user is None:
        raise UserNotFoundError("user not found")

    return user


def list_users(
    db: Session, 
    skip: int = 0, 
    limit: int = 20
) -> tuple[list[User], int]:
    
    skip = max(skip, 0)
    limit = min(max(limit, 1), 100)

    total = db.scalar(select(func.count()).select_from(User)) or 0
    statement = select(User).order_by(User.user_id).offset(skip).limit(limit)
    items = list(db.scalars(statement).all())

    return items, total


def create_user(db: Session, 
                data: UserCreate
                ) -> User:
    values = data.model_dump(exclude={"password"})
    user = User(**values, 
                password_hash=hash_password(data.password)
                )

    db.add(user)
    commit_or_rollback(db)
    db.refresh(user)
    logger.info("New user created",
                extra={"user_id": user.user_id}
                )

    return user


def apply_profile_changes(
    db: Session, 
    user: User, 
    changes: dict[str, Optional[str]]
) -> User:
    if not changes:
        return user

    for field, value in changes.items():
        setattr(user, field, value)

    commit_or_rollback(db)
    db.refresh(user)
    logger.info(
        "user profile updated",
        extra={
               "user_id": user.user_id, 
               "fields": sorted(changes)
               },
    )

    return user


def update_profile(db: Session, 
                   user_id: int, 
                   data: UserUpdate
                   ) -> User:
    
    user = get_user_or_raise(db, user_id)
    changes = data.model_dump(exclude_unset=True)

    return apply_profile_changes(db, user, changes)


def replace_profile(db: Session, 
                    user_id: int, 
                    data: UserUpdate
                    ) -> User:
    
    user = get_user_or_raise(db, user_id)

    return apply_profile_changes(db, user, 
                                 data.model_dump()
                                 )


def ensure_admin_remains(db: Session, user: User) -> None:
    if not (user.is_admin and user.is_active):
        return

    # row lock stops two admins removing each other at the same time
    statement = (
        select(User.user_id)
        .where(User.is_admin.is_(True), User.is_active.is_(True))
        .with_for_update()
    )
    admin_ids = db.scalars(statement).all()

    if len(admin_ids) <= 1:
        logger.warning(
            "last admin removal blocked", 
            extra={"user_id": user.user_id}
        )
        raise LastAdminError("the last active admin cannot be removed")


def set_user_active(
    db: Session,
    user_id: int, 
    data: UserAdminUpdate
) -> User:
    
    user = get_user_or_raise(db, user_id)

    if not data.is_active:
        ensure_admin_remains(db, user)

    user.is_active = data.is_active
    commit_or_rollback(db)
    db.refresh(user)
    logger.info(
        "user active flag set",
        extra={
            "user_id": user.user_id, 
            "is_active": user.is_active
            },
    )

    return user


def change_password(db: Session, 
                    user_id: int, 
                    data: PasswordChange
                    ) -> None:
    
    user = get_user_or_raise(db, user_id)

    if not verify_password(data.current_password, 
                           user.password_hash):
        logger.warning(
            "password change rejected", 
            extra={"user_id": user.user_id}
        )
        raise InvalidCredentialsError("current password is incorrect")

    user.password_hash = hash_password(data.new_password)
    commit_or_rollback(db)
    logger.info("user password changed",
                extra={"user_id": user.user_id}
                )


def authenticate_user(db: Session, 
                      username: str, 
                      password: str
                      ) -> User:
    
    user = get_user_by_username(db, username)

    if user is None:
        verify_password(password, DUMMY_HASH)
        raise InvalidCredentialsError("invalid credentials")

    if not verify_password(password, user.password_hash):
        logger.warning("login rejected", extra={"user_id": user.user_id})
        raise InvalidCredentialsError("invalid credentials")

    if not user.is_active:
        logger.warning("inactive user login", extra={"user_id": user.user_id})
        raise InvalidCredentialsError("invalid credentials")

    return user


def soft_delete_user(db: Session, 
                     user_id: int
                     ) -> User:
    
    user = get_user_or_raise(db, user_id)

    ensure_admin_remains(db, user)
    user.is_active = False
    commit_or_rollback(db)
    db.refresh(user)
    logger.info("user soft deleted", 
                extra={"user_id": user.user_id}
                )

    return user


def delete_user(db: Session, 
                user_id: int
                ) -> None:
    
    user = get_user_or_raise(db, user_id)

    ensure_admin_remains(db, user)
    db.delete(user)
    commit_or_rollback(db)
    logger.info("user deleted", extra={"user_id": user_id})
