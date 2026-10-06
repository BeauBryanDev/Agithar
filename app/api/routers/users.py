from typing import Annotated

from fastapi import (
    APIRouter,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)

from app.api.deps import CurrentAdmin, CurrentUser, DbSession
from app.core.auth import create_access_token
from app.core.logging import get_logger
from app.db.postgresql.users import User
from app.schemas.users import (
    AdminUserCreate,
    PasswordChange,
    Token,
    UserAdminUpdate,
    UserCreate,
    UserList,
    UserLogin,
    UserRead,
    UserUpdate,
)
from app.security.rate_limit import (
    LOGIN_IP_LIMITER,
    LOGIN_USER_LIMITER,
    PASSWORD_LIMITER,
    client_ip,
    ensure_not_limited,
)
from app.services import users_service as service


logger = get_logger("api.users")

router = APIRouter(prefix="/users", tags=["users"])

UserId = Annotated[int, Path(ge=1)]


def not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
    )


def forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail="Access denied"
    )


def last_admin_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="The last active admin cannot be removed",
    )


@router.post("/login", response_model=Token)
def login(
    credentials: UserLogin, request: Request, db: DbSession
) -> Token:
    ip = client_ip(request)
    pair = f"{ip}|{credentials.username.lower()}"

    ensure_not_limited(LOGIN_IP_LIMITER, ip)
    ensure_not_limited(LOGIN_USER_LIMITER, pair)

    try:
        user = service.authenticate_user(
            db, credentials.username, credentials.password
        )
    except service.InvalidCredentialsError:
        LOGIN_IP_LIMITER.record_failure(ip)
        LOGIN_USER_LIMITER.record_failure(pair)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    LOGIN_USER_LIMITER.reset(pair)

    return Token(access_token=create_access_token(user.user_id))


@router.get("/me", response_model=UserRead)
def read_me(current_user: CurrentUser) -> User:
    return current_user


@router.patch("/me", response_model=UserRead)
def patch_me(
    data: UserUpdate, current_user: CurrentUser, db: DbSession
) -> User:
    return service.update_profile(db, current_user.user_id, data)


@router.put("/me", response_model=UserRead)
def replace_me(
    data: UserUpdate, current_user: CurrentUser, db: DbSession
) -> User:
    return service.replace_profile(db, current_user.user_id, data)


@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def change_my_password(
    data: PasswordChange, current_user: CurrentUser, db: DbSession
) -> Response:
    key = str(current_user.user_id)
    ensure_not_limited(PASSWORD_LIMITER, key)

    try:
        service.change_password(db, current_user.user_id, data)
    except service.InvalidCredentialsError:
        PASSWORD_LIMITER.record_failure(key)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    PASSWORD_LIMITER.reset(key)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_me(current_user: CurrentUser, db: DbSession) -> Response:
    try:
        service.soft_delete_user(db, current_user.user_id)
    except service.LastAdminError:
        raise last_admin_conflict()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    data: AdminUserCreate, admin: CurrentAdmin, db: DbSession
) -> User:
    # Admin only. The admin chooses the role of the new account.
    try:
        user = service.create_user(db, data, is_admin=data.is_admin)
    except service.UserAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already in use",
        )

    if user.is_admin:
        logger.warning(
            "admin account created",
            extra={"user_id": user.user_id, "by": admin.user_id},
        )

    return user


@router.get("", response_model=UserList)
def list_users(
    admin: CurrentAdmin,
    db: DbSession,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> UserList:
    items, total = service.list_users(db, skip, limit)

    return UserList(
        items=[UserRead.model_validate(item) for item in items],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/{user_id}", response_model=UserRead)
def read_user(
    user_id: UserId, current_user: CurrentUser, db: DbSession
) -> User:
    if not current_user.is_admin and current_user.user_id != user_id:
        raise forbidden()

    user = service.get_user_by_id(db, user_id)

    if user is None:
        raise not_found()

    return user


@router.patch("/{user_id}/active", response_model=UserRead)
def set_user_active(
    user_id: UserId,
    data: UserAdminUpdate,
    admin: CurrentAdmin,
    db: DbSession,
) -> User:
    try:
        return service.set_user_active(db, user_id, data)
    except service.UserNotFoundError:
        raise not_found()
    except service.LastAdminError:
        raise last_admin_conflict()


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: UserId,
    admin: CurrentAdmin,
    db: DbSession,
    permanent: Annotated[bool, Query()] = False,
) -> Response:
    # Default: deactivate (reversible). permanent=true erases an account
    # that is already deactivated, and never your own.
    try:
        if permanent:
            service.delete_user_permanently(db, user_id, admin.user_id)
        else:
            service.soft_delete_user(db, user_id)
    except service.UserNotFoundError:
        raise not_found()
    except service.LastAdminError:
        raise last_admin_conflict()
    except service.SelfDeleteError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You cannot permanently delete your own account",
        )
    except service.UserStillActiveError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Deactivate the user before deleting it permanently",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
