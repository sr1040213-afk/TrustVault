from pathlib import Path
from app.extensions import db
from app.models import User, Document, Grant, AuditEvent
from app.security import can_access, append_audit

def login(client, email):
    return client.post("/login", data={"email": email, "password": "correct-horse-battery-staple"}, follow_redirects=True)

def seed_doc(app):
    with app.app_context():
        owner = User.query.filter_by(email="owner@test.local").first()
        doc = Document(owner_id=owner.id, title="Secret", category="Finance",
                       original_name="secret.txt", storage_name="secret-object",
                       sha256="a"*64, size=6, mime_type="text/plain")
        db.session.add(doc); db.session.commit()
        Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
        (Path(app.config["UPLOAD_FOLDER"]) / "secret-object").write_text("secret")
        return doc.id

def test_other_user_cannot_view_or_download(client, app):
    doc_id = seed_doc(app)
    login(client, "other@test.local")
    assert client.get(f"/documents/{doc_id}").status_code == 404
    assert client.get(f"/documents/{doc_id}/download").status_code == 404

def test_viewer_cannot_upload(client):
    login(client, "viewer@test.local")
    assert client.get("/documents/upload").status_code == 403

def test_revoked_grant_denies_next_request(client, app):
    doc_id = seed_doc(app)
    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        db.session.add(Grant(document_id=doc_id, user_id=viewer.id, permission="read"))
        db.session.commit()
    login(client, "viewer@test.local")
    assert client.get(f"/documents/{doc_id}").status_code == 200
    with app.app_context():
        grant = Grant.query.filter_by(document_id=doc_id).first()
        from app.models import utcnow
        grant.revoked_at = utcnow()
        db.session.commit()
    assert client.get(f"/documents/{doc_id}").status_code == 404

def test_viewer_cannot_edit_document(client, app):
    doc_id = seed_doc(app)
    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        db.session.add(Grant(document_id=doc_id, user_id=viewer.id, permission="read"))
        db.session.commit()
    login(client, "viewer@test.local")
    response = client.post(f"/documents/{doc_id}/edit", data={"title": "Hacked"})
    assert response.status_code == 403

def test_admin_is_not_automatically_document_reader(app):
    with app.app_context():
        doc_id = seed_doc(app)
        admin = User.query.filter_by(email="admin@test.local").first()
        doc = db.session.get(Document, doc_id)
        assert can_access(doc, admin, "read") is False

def test_audit_hmac_detects_tampering(app):
    from app.security import append_audit, verify_audit_chain
    with app.app_context():
        append_audit("test_event", detail="original")
        db.session.commit()
        assert verify_audit_chain() is True
        event = __import__('app.models', fromlist=['AuditEvent']).AuditEvent.query.first()
        event.detail = "tampered"
        db.session.commit()
        assert verify_audit_chain() is False

def test_download_rejects_modified_blob(client, app):
    from pathlib import Path
    doc_id = seed_doc(app)
    login(client, "owner@test.local")
    with app.app_context():
        doc = db.session.get(Document, doc_id)
        (Path(app.config["UPLOAD_FOLDER"]) / doc.storage_name).write_text("altered")
    assert client.get(f"/documents/{doc_id}/download").status_code == 409

def test_upload_rejects_fake_pdf(client):
    import io
    login(client, "owner@test.local")
    response = client.post("/documents/upload", data={"title": "fake", "category": "test", "file": (io.BytesIO(b"not a pdf"), "fake.pdf")}, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"supported file" in response.data
def test_new_registration_defaults_to_viewer(client, app):
    response = client.post("/register", data={
        "name": "New Viewer",
        "email": "newviewer@test.local",
        "password": "strong-password-123"
    }, follow_redirects=True)

    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email="newviewer@test.local").first()
        assert user is not None
        assert user.role == "viewer"


def test_registration_cannot_self_assign_admin(client, app):
    response = client.post("/register", data={
        "name": "Fake Admin",
        "email": "fakeadmin@test.local",
        "password": "strong-password-123",
        "role": "admin"
    }, follow_redirects=True)

    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email="fakeadmin@test.local").first()
        assert user is not None
        assert user.role == "viewer"


def test_registration_cannot_self_assign_owner(client, app):
    response = client.post("/register", data={
        "name": "Fake Owner",
        "email": "fakeowner@test.local",
        "password": "strong-password-123",
        "role": "owner"
    }, follow_redirects=True)

    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email="fakeowner@test.local").first()
        assert user is not None
        assert user.role == "viewer"

def test_owner_cannot_change_user_role(client, app):
    login(client, "owner@test.local")

    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        viewer_id = viewer.id

    response = client.post(
        f"/admin/users/{viewer_id}/role",
        data={"role": "admin"}
    )

    assert response.status_code == 403

    with app.app_context():
        viewer = db.session.get(User, viewer_id)
        assert viewer.role == "viewer"


def test_viewer_cannot_access_admin_dashboard(client):
    login(client, "viewer@test.local")

    response = client.get("/admin")

    assert response.status_code == 403


def test_admin_cannot_change_own_role(client, app):
    login(client, "admin@test.local")

    with app.app_context():
        admin = User.query.filter_by(email="admin@test.local").first()
        admin_id = admin.id

    response = client.post(
        f"/admin/users/{admin_id}/role",
        data={"role": "viewer"}
    )

    assert response.status_code == 400

    with app.app_context():
        admin = db.session.get(User, admin_id)
        assert admin.role == "admin"


def test_inactive_user_cannot_login(client, app):
    with app.app_context():
        user = User.query.filter_by(email="viewer@test.local").first()
        user.active = False
        db.session.commit()

    response = client.post("/login", data={
        "email": "viewer@test.local",
        "password": "correct-horse-battery-staple"
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Invalid credentials or inactive account" in response.data

def test_deactivated_user_existing_session_is_revoked(client, app):
    login(client, "viewer@test.local")

    with app.app_context():
        user = User.query.filter_by(email="viewer@test.local").first()
        user.active = False
        db.session.commit()

    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.location

def test_csrf_protection_rejects_post_without_token(app):
    app.config["WTF_CSRF_ENABLED"] = True

    client = app.test_client()

    response = client.post("/login", data={
        "email": "owner@test.local",
        "password": "correct-horse-battery-staple"
    })

    assert response.status_code == 400
def test_security_headers_are_present(client):
    response = client.get("/")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"
def test_revoked_grant_can_be_regranted(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        viewer_id = viewer.id

        db.session.add(
            Grant(
                document_id=doc_id,
                user_id=viewer_id,
                permission="read"
            )
        )
        db.session.commit()

    login(client, "viewer@test.local")
    assert client.get(f"/documents/{doc_id}").status_code == 200

    with app.app_context():
        grant = Grant.query.filter_by(
            document_id=doc_id,
            user_id=viewer_id
        ).first()

        from app.models import utcnow
        grant.revoked_at = utcnow()
        db.session.commit()

    assert client.get(f"/documents/{doc_id}").status_code == 404

    login(client, "owner@test.local")

    response = client.post(
        f"/documents/{doc_id}/share",
data={
            "user_id": viewer_id,
            "permission": "read"
        },
        follow_redirects=True
    )

    assert response.status_code == 200

    login(client, "viewer@test.local")
    assert client.get(f"/documents/{doc_id}").status_code == 200

    with app.app_context():
        grant = Grant.query.filter_by(
            document_id=doc_id,
            user_id=viewer_id
        ).first()

        assert grant.revoked_at is None
        assert grant.permission == "read"
def test_viewer_cannot_upload_using_post(client):
    import io

    login(client, "viewer@test.local")

    response = client.post(
        "/documents/upload",
        data={
            "title": "Unauthorized Upload",
            "category": "General",
            "file": (io.BytesIO(b"fake content"), "test.txt")
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 403
def test_admin_cannot_upload_using_post(client, app):
    import io

    login(client, "admin@test.local")

    response = client.post(
        "/documents/upload",
        data={
            "title": "Admin Unauthorized Upload",
            "category": "General",
            "file": (io.BytesIO(b"fake content"), "test.txt")
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 403

    with app.app_context():
        event = AuditEvent.query.filter_by(
            action="document_upload",
            outcome="denied"
        ).order_by(AuditEvent.id.desc()).first()

        assert event is not None
        assert "role=admin" in event.detail
def test_admin_search_does_not_show_unshared_documents(client):
    from app.models import Document

    login(client, "owner@test.local")
    doc_id = seed_doc(client.application)

    client.get("/logout")
    login(client, "admin@test.local")

    response = client.get("/documents")

    assert response.status_code == 200
    assert b"Secret" not in response.data


def test_owner_revoke_route_immediately_blocks_viewer(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        grant = Grant(
            document_id=doc_id,
            user_id=viewer.id,
            permission="read"
        )
        db.session.add(grant)
        db.session.commit()
        viewer_id = viewer.id

    login(client, "owner@test.local")

    response = client.post(
        f"/documents/{doc_id}/revoke/{viewer_id}"
    )
    assert response.status_code == 302

    client.post("/logout")
    login(client, "viewer@test.local")

    assert client.get(f"/documents/{doc_id}").status_code == 404
    assert client.get(f"/documents/{doc_id}/download").status_code == 404

def test_viewer_with_read_grant_can_download_document(client, app):
    import hashlib

    doc_id = seed_doc(app)

    with app.app_context():
        doc = db.session.get(Document, doc_id)
        doc.sha256 = hashlib.sha256(b"secret").hexdigest()

        viewer = User.query.filter_by(email="viewer@test.local").first()
        db.session.add(Grant(
            document_id=doc_id,
            user_id=viewer.id,
            permission="read"
        ))
        db.session.commit()

    login(client, "viewer@test.local")

    response = client.get(f"/documents/{doc_id}/download")

    assert response.status_code == 200
    assert response.data == b"secret"

def test_owner_can_share_document_with_viewer_using_route(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        viewer_id = viewer.id

    login(client, "owner@test.local")

    response = client.post(
        f"/documents/{doc_id}/share",
        data={
            "user_id": str(viewer_id),
            "permission": "read",
        },
    )
    assert response.status_code == 302

    with app.app_context():
        grant = Grant.query.filter_by(
            document_id=doc_id,
            user_id=viewer_id,
        ).first()
        assert grant is not None
        assert grant.permission == "read"
        assert grant.revoked_at is None

    client.post("/logout")
    login(client, "viewer@test.local")

    assert client.get(f"/documents/{doc_id}").status_code == 200
def test_invalid_share_permission_is_audited(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        viewer_id = viewer.id

    login(client, "owner@test.local")

    response = client.post(
        f"/documents/{doc_id}/share",
        data={
            "user_id": str(viewer_id),
            "permission": "admin",
        },
    )

    assert response.status_code == 400

    with app.app_context():
        event = AuditEvent.query.filter_by(
            action="permission_grant",
            outcome="denied",
            document_id=doc_id,
        ).order_by(AuditEvent.id.desc()).first()

        assert event is not None
        assert "Invalid share target or permission" in event.detail
def test_non_owner_cannot_share_another_owners_document(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        viewer_id = viewer.id

    login(client, "viewer@test.local")

    response = client.post(
        f"/documents/{doc_id}/share",
        data={
            "user_id": str(viewer_id),
            "permission": "read",
        },
    )

    assert response.status_code == 403

def test_viewer_with_edit_grant_can_edit_document(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        viewer = User.query.filter_by(email="viewer@test.local").first()
        db.session.add(Grant(
            document_id=doc_id,
            user_id=viewer.id,
            permission="edit",
        ))
        db.session.commit()

    login(client, "viewer@test.local")

    response = client.post(
        f"/documents/{doc_id}/edit",
        data={"title": "Updated by Viewer"},
    )

    assert response.status_code == 302

    with app.app_context():
        doc = db.session.get(Document, doc_id)
        assert doc.title == "Updated by Viewer"

def test_admin_can_delete_document_without_read_access(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        admin = User.query.filter_by(email="admin@test.local").first()
        assert can_access(db.session.get(Document, doc_id), admin, "read") is False

    login(client, "admin@test.local")

    response = client.post(f"/admin/documents/{doc_id}/delete")
    assert response.status_code == 302

    with app.app_context():
        doc = db.session.get(Document, doc_id)
        assert doc.deleted_at is not None
def test_admin_dashboard_displays_document_metadata_without_content_access(client, app):
    doc_id = seed_doc(app)
    login(client, "admin@test.local")

    response = client.get("/admin")

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert "Uploaded documents" in html
    assert "Secret" in html
    assert "secret.txt" in html
    assert "owner@test.local" in html
    assert f"/documents/{doc_id}/download" not in html
def test_admin_dashboard_displays_document_sharing_metadata(client, app):
    doc_id = seed_doc(app)

    with app.app_context():
        doc = db.session.get(Document, doc_id)
        viewer = User.query.filter_by(email="viewer@test.local").first()

        grant = Grant(
            document_id=doc.id,
            user_id=viewer.id,
            permission="read"
        )
        db.session.add(grant)
        db.session.commit()

    login(client, "admin@test.local")

    response = client.get("/admin")

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert "Document sharing monitor" in html
    assert "Shared with:" in html
    assert "viewer@test.local" in html
    assert "read" in html
def test_admin_dashboard_displays_all_audit_events(client, app):
    with app.app_context():
        for i in range(105):
            append_audit(
                "audit_visibility_test",
                detail=f"visibility-marker-{i}"
            )
        db.session.commit()

    login(client, "admin@test.local")

    response = client.get("/admin")

    assert response.status_code == 200

    html = response.get_data(as_text=True)

    assert "visibility-marker-0" in html
    assert "visibility-marker-104" in html
    assert "audit visibility test" in html
def test_user_can_view_own_activity_history(client, app):
    login(client, "viewer@test.local")

    response = client.get("/activity")

    assert response.status_code == 200
    assert b"My Activity History" in response.data


def test_activity_history_requires_login(client):
    response = client.get("/activity")

    assert response.status_code == 302
def test_user_cannot_view_another_users_activity(client, app):
    with app.app_context():
        owner = User.query.filter_by(email="owner@test.local").first()
        viewer = User.query.filter_by(email="viewer@test.local").first()

        append_audit(
            "private_activity_marker",
            detail="OWNER_PRIVATE_ACTIVITY",
            actor_id=owner.id
        )
        db.session.commit()

    login(client, "viewer@test.local")
    response = client.get("/activity")

    assert response.status_code == 200
    assert b"OWNER_PRIVATE_ACTIVITY" not in response.data
def test_user_cannot_view_another_users_activity(client, app):
    with app.app_context():
        owner = User.query.filter_by(email="owner@test.local").first()
        owner_id = owner.id

    with client.application.test_request_context():
        from flask_login import login_user
        with app.app_context():
            owner = db.session.get(User, owner_id)
            login_user(owner)
            append_audit(
                "private_activity_marker",
                detail="OWNER_PRIVATE_ACTIVITY"
            )
            db.session.commit()

    login(client, "viewer@test.local")
    response = client.get("/activity")

    assert response.status_code == 200
    assert b"OWNER_PRIVATE_ACTIVITY" not in response.data
def test_user_cannot_view_another_users_activity(client, app):
    owner_client = app.test_client()
    viewer_client = app.test_client()

    login(owner_client, "owner@test.local")
    owner_client.get("/dashboard")

    with app.app_context():
        owner_event = AuditEvent.query.filter_by(
            actor_id=User.query.filter_by(email="owner@test.local").first().id
        ).first()
        assert owner_event is not None

    login(viewer_client, "viewer@test.local")
    response = viewer_client.get("/activity")

    assert response.status_code == 200
    assert b"OWNER_PRIVATE_ACTIVITY" not in response.data
def test_user_cannot_view_another_users_activity(client, app):
    owner_client = app.test_client()
    viewer_client = app.test_client()

    doc_id = seed_doc(app)

    # Owner creates a document-view activity event
    login(owner_client, "owner@test.local")
    response = owner_client.get(f"/documents/{doc_id}")
    assert response.status_code == 200

    # Viewer must not see the owner's activity
    login(viewer_client, "viewer@test.local")
    response = viewer_client.get("/activity")

    assert response.status_code == 200
    assert b"document_view" not in response.data
