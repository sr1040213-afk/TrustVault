import pytest
from app import create_app
from app.extensions import db
from app.models import User

@pytest.fixture
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "UPLOAD_FOLDER": str(tmp_path / "private"),
        "SECRET_KEY": "test-secret",
        "AUDIT_HMAC_KEY": b"test-audit-secret",
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
        for name, email, role in [("Owner", "owner@test.local", "owner"),
                                  ("Viewer", "viewer@test.local", "viewer"),
                                  ("Other", "other@test.local", "owner"),
                                  ("Admin", "admin@test.local", "admin")]:
            u = User(name=name, email=email, role=role)
            u.set_password("correct-horse-battery-staple")
            db.session.add(u)
        db.session.commit()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()
