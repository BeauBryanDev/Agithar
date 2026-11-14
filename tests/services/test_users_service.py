import pytest
from sqlalchemy.orm import Session

from app.schemas.users import (
    AdminUserCreate,
    PasswordChange,
    UserAdminUpdate,
    UserUpdate,
)
from app.services import users_service as svc


PASSWORD = "correct-horse-battery"


def new_user(
    db: Session,
    username: str = "operator1",
    is_admin: bool = False,
    **extra: object,
):
    data = AdminUserCreate(
        name="Test User",
        username=username,
        email=f"{username}@example.com",
        password=PASSWORD,
        **extra,
    )

    return svc.create_user(db, data, is_admin=is_admin)


def test_create_user_role_comes_only_from_argument(db_session: Session):
    data = AdminUserCreate(
        name="Mallory",
        username="mallory",
        email="Mallory@Example.com",
        password=PASSWORD,
        is_admin=True,
    )
    user = svc.create_user(db_session, data)

    assert user.is_admin is False
    assert user.email == "mallory@example.com"
    assert user.password_hash != PASSWORD


def test_create_admin_when_argument_is_true(db_session: Session):
    user = new_user(db_session, "boss", is_admin=True)

    assert user.is_admin is True
    assert user.is_active is True


def test_duplicate_username_or_email_rejected(db_session: Session):
    new_user(db_session, "twin")

    with pytest.raises(svc.UserAlreadyExistsError):
        new_user(db_session, "twin")

    assert svc.get_user_by_username(db_session, "twin") is not None


def test_authenticate_success(db_session: Session):
    created = new_user(db_session)
    user = svc.authenticate_user(db_session, "operator1", PASSWORD)

    assert user.user_id == created.user_id


@pytest.mark.parametrize(
    "username, password",
    [("operator1", "wrong-password-123"), ("nobody", PASSWORD)],
)
def test_authenticate_rejects_bad_credentials(
    db_session: Session, username: str, password: str
):
    new_user(db_session)

    with pytest.raises(svc.InvalidCredentialsError) as info:
        svc.authenticate_user(db_session, username, password)

    assert str(info.value) == "invalid credentials"


def test_inactive_user_cannot_log_in(db_session: Session):
    new_user(db_session, "boss", is_admin=True)
    user = new_user(db_session)
    svc.set_user_active(
        db_session, user.user_id, UserAdminUpdate(is_active=False)
    )

    with pytest.raises(svc.InvalidCredentialsError):
        svc.authenticate_user(db_session, "operator1", PASSWORD)


def test_update_profile_changes_only_sent_fields(db_session: Session):
    user = new_user(db_session, city="Paris", country="France")
    updated = svc.update_profile(
        db_session, user.user_id, UserUpdate(city="Lyon")
    )

    assert updated.city == "Lyon"
    assert updated.country == "France"
    assert updated.username == "operator1"


def test_change_password_checks_current(db_session: Session):
    user = new_user(db_session)
    new_password = "another-long-password"

    with pytest.raises(svc.InvalidCredentialsError):
        svc.change_password(
            db_session,
            user.user_id,
            PasswordChange(
                current_password="not-the-password",
                new_password=new_password,
            ),
        )

    svc.change_password(
        db_session,
        user.user_id,
        PasswordChange(current_password=PASSWORD, new_password=new_password),
    )

    assert svc.authenticate_user(db_session, "operator1", new_password)


def test_last_admin_cannot_be_removed(db_session: Session):
    admin = new_user(db_session, "boss", is_admin=True)

    with pytest.raises(svc.LastAdminError):
        svc.soft_delete_user(db_session, admin.user_id)

    with pytest.raises(svc.LastAdminError):
        svc.set_user_active(
            db_session, admin.user_id, UserAdminUpdate(is_active=False)
        )

    assert svc.get_user_by_id(db_session, admin.user_id).is_active


def test_permanent_delete_safeguards(db_session: Session):
    admin = new_user(db_session, "boss", is_admin=True)
    user = new_user(db_session)

    with pytest.raises(svc.SelfDeleteError):
        svc.delete_user_permanently(db_session, admin.user_id, admin.user_id)

    with pytest.raises(svc.UserStillActiveError):
        svc.delete_user_permanently(db_session, user.user_id, admin.user_id)

    svc.soft_delete_user(db_session, user.user_id)
    svc.delete_user_permanently(db_session, user.user_id, admin.user_id)

    assert svc.get_user_by_id(db_session, user.user_id) is None
