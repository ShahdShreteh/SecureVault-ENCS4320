import pytest

from src.auth.auth_service import AuthService


@pytest.fixture
def service(tmp_path):
    return AuthService(tmp_path / "users.db")
