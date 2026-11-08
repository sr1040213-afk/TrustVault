import os, uuid
import hmac
from pathlib import Path
from flask import render_template, request, redirect, url_for, flash, abort, send_file, current_app
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import or_
from werkzeug.utils import secure_filename
from .extensions import db
from .models import User, Document, Grant, AuditEvent
from .security import allowed_file, sha256_file, validate_file_content, can_access, append_audit, verify_audit_chain

def register_routes(app):
    
    @app.route("/bootstrap-roles", methods=["GET", "POST"])
    def bootstrap_roles():
        secret = os.getenv("BOOTSTRAP_SECRET", "")

        # Setup is disabled unless a secret is configured.
        if not secret:
            abort(404)

        # This setup can run only once, before any Admin exists.
        if User.query.filter_by(role="admin").first():
            abort(404)

        if request.method == "POST":
            supplied_secret = request.form.get("bootstrap_secret", "")
            current_app.logger.info(
            "BOOTSTRAP CHECK: configured=%s, entered_length=%s, saved_length=%s",
            bool(secret),
            len(supplied_secret),
            len(secret)
)

            if not hmac.compare_digest(supplied_secret, secret):
                flash("Invalid setup credentials.", "danger")
                return render_template("bootstrap_roles.html"), 403

            admin_email = request.form.get("admin_email", "").strip().lower()
            owner_email = request.form.get("owner_email", "").strip().lower()

            if not admin_email or not owner_email or admin_email == owner_email:
                flash("Enter two different valid email addresses.", "danger")
                return render_template("bootstrap_roles.html"), 400

            admin_user = User.query.filter_by(email=admin_email).first()
            owner_user = User.query.filter_by(email=owner_email).first()

            if (
                not admin_user or not owner_user
                or not admin_user.active or not owner_user.active
            ):
                flash("Both accounts must exist and be active.", "danger")
                return render_template("bootstrap_roles.html"), 400

            try:
                admin_user.role = "admin"
                owner_user.role = "owner"

                append_audit(
                    "initial_admin_assigned",
                    detail=f"Admin account configured: {admin_email}"
                )
                append_audit(
                    "initial_owner_assigned",
                    detail=f"Owner account configured: {owner_email}"
                )

                db.session.commit()
                return "Initial Admin and Owner roles configured successfully."

            except Exception:
                db.session.rollback()
                current_app.logger.exception("Initial role setup failed")
                abort(500)

        return render_template("bootstrap_roles.html")

    @app.context_processor
    def inject_globals():
        return {"app_name": "TrustVault"}

    @app.get("/")
    def home():
        return render_template("home.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not name or len(name) > 100 or "@" not in email or len(password) < 12:
                flash("Enter valid details. Password must be at least 12 characters.", "danger")
                return render_template("auth.html", mode="register")
            if User.query.filter_by(email=email).first():
                flash("An account with this email already exists.", "warning")
                return render_template("auth.html", mode="register")
            user = User(name=name, email=email, role="viewer")
            user.set_password(password)
            db.session.add(user)
            db.session.flush()
            append_audit("user_registered", detail=email)
            db.session.commit()
            login_user(user)
            return redirect(url_for("dashboard"))
        return render_template("auth.html", mode="register")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            user = User.query.filter_by(email=email).first()
            if user and user.active and user.check_password(request.form.get("password", "")):
                login_user(user)
                append_audit("login", detail="Successful login")
                db.session.commit()
                return redirect(url_for("admin_dashboard" if user.role == "admin" else "dashboard"))
            append_audit("login", outcome="denied", detail=f"Failed login for {email}")
            db.session.commit()
            flash("Invalid credentials or inactive account.", "danger")
        return render_template("auth.html", mode="login")

    @app.post("/logout")
    @login_required
    def logout():
        append_audit("logout")
        db.session.commit()
        logout_user()
        return redirect(url_for("home"))
    @app.get("/activity")
    @login_required
    def activity_history():
        events = AuditEvent.query.filter_by(
            actor_id=current_user.id
        ).order_by(AuditEvent.created_at.desc()).all()

        return render_template("activity.html", events=events)
    @app.get("/dashboard")
    @login_required
    def dashboard():
        owned = Document.query.filter_by(owner_id=current_user.id, deleted_at=None).order_by(Document.created_at.desc()).all()
        grants = Grant.query.filter_by(user_id=current_user.id, revoked_at=None).all()
        received = [g.document for g in grants if g.document and g.document.deleted_at is None]
        return render_template("dashboard.html", owned=owned, received=received)

    @app.route("/documents/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if current_user.role != "owner":
            append_audit(
                "document_upload",
                outcome="denied",
                detail=f"Unauthorized upload attempt by role={current_user.role}"
            )
            db.session.commit()
            abort(403)

        if request.method == "POST":
            file = request.files.get("file")
            title = request.form.get("title", "").strip()
            category = request.form.get("category", "General").strip()[:80]

            if (
                not file
                or not file.filename
                or not allowed_file(file.filename)
                or not title
                or not validate_file_content(file.filename, file.stream)
            ):
                flash("Choose a supported file and enter a title.", "danger")
                return render_template("upload.html")

            original = secure_filename(file.filename)
            digest = sha256_file(file.stream)
            storage_name = uuid.uuid4().hex
            destination = Path(current_app.config["UPLOAD_FOLDER"]) / storage_name
            file.save(destination)

            doc = Document(
                owner_id=current_user.id,
                title=title[:180],
                category=category or "General",
                original_name=original,
                storage_name=storage_name,
                sha256=digest,
                size=destination.stat().st_size,
                mime_type=file.mimetype or "application/octet-stream"
            )

            db.session.add(doc)
            db.session.flush()

            append_audit(
                "document_uploaded",
                document_id=doc.id,
                detail=f"sha256={digest}"
            )

            db.session.commit()
            flash("Document uploaded securely.", "success")
            return redirect(url_for("dashboard"))

        return render_template("upload.html")

    @app.get("/documents")
    @login_required
    def search_documents():
        q = request.args.get("q", "").strip()
        category = request.args.get("category", "").strip()
        query = Document.query.filter(Document.deleted_at.is_(None))
        if current_user.role != "admin":
            owned_ids = [d.id for d in Document.query.filter_by(owner_id=current_user.id, deleted_at=None).all()]
            grant_ids = [g.document_id for g in Grant.query.filter_by(user_id=current_user.id, revoked_at=None).all()]
            query = query.filter(Document.id.in_(owned_ids + grant_ids))
        if q:
            query = query.filter(or_(Document.title.ilike(f"%{q}%"), Document.original_name.ilike(f"%{q}%")))
        if category:
            query = query.filter(Document.category.ilike(f"%{category}%"))
        docs = query.order_by(Document.created_at.desc()).all()
        docs = [d for d in docs if can_access(d, current_user, "read")]
        return render_template("search.html", documents=docs, q=q, category=category)

    @app.get("/documents/<int:document_id>")
    @login_required
    def document_detail(document_id):
        doc = db.session.get(Document, document_id)
        if not doc or not can_access(doc, current_user, "read"):
            append_audit("document_view", outcome="denied", document_id=document_id, detail="Access denied")
            db.session.commit()
            abort(404)
        append_audit("document_view", document_id=doc.id)
        db.session.commit()
        grants = Grant.query.filter_by(document_id=doc.id, revoked_at=None).all() if doc.owner_id == current_user.id else []
        return render_template("detail.html", document=doc, grants=grants, can_edit=can_access(doc, current_user, "edit"), users=User.query.filter_by(active=True).all())

    @app.get("/documents/<int:document_id>/download")
    @login_required
    def download(document_id):
        doc = db.session.get(Document, document_id)
        if not doc or not can_access(doc, current_user, "read"):
            append_audit("document_download", outcome="denied", document_id=document_id, detail="Access denied")
            db.session.commit()
            abort(404)
        path = Path(current_app.config["UPLOAD_FOLDER"]) / doc.storage_name
        if not path.is_file():
            append_audit("document_download", outcome="error", document_id=doc.id, detail="Stored object missing")
            db.session.commit()
            abort(404)
        import hashlib, hmac
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if not hmac.compare_digest(actual_hash, doc.sha256):
            append_audit("document_download", outcome="integrity_failure", document_id=doc.id, detail="SHA-256 mismatch")
            db.session.commit()
            abort(409)
        append_audit("document_download", document_id=doc.id)
        db.session.commit()
        return send_file(path, as_attachment=True, download_name=doc.original_name)

    @app.post("/documents/<int:document_id>/share")
    @login_required
    def share(document_id):
        doc = db.session.get(Document, document_id)
        if not doc or doc.owner_id != current_user.id or doc.deleted_at is not None:
            append_audit("permission_grant", outcome="denied", document_id=document_id)
            db.session.commit()
            abort(403
            )
        target = db.session.get(User, request.form.get("user_id", type=int))
        permission = request.form.get("permission")

        if not target or target.id == current_user.id or permission not in {"read", "edit"}:
            append_audit(
                "permission_grant",
                outcome="denied",
                document_id=doc.id,
                detail="Invalid share target or permission"
            )
            db.session.commit()
            abort(400)
        grant = Grant.query.filter_by(document_id=doc.id, user_id=target.id).first()
        if grant:
            grant.permission, grant.revoked_at = permission, None
        else:
            db.session.add(Grant(document_id=doc.id, user_id=target.id, permission=permission))
        append_audit("permission_grant", document_id=doc.id, detail=f"user={target.id};permission={permission}")
        db.session.commit()
        flash("Access granted.", "success")
        return redirect(url_for("document_detail", document_id=doc.id))

    @app.post("/documents/<int:document_id>/revoke/<int:user_id>")
    @login_required
    def revoke(document_id, user_id):
        doc = db.session.get(Document, document_id)

        if not doc or doc.owner_id != current_user.id:
            append_audit(
                "permission_revoke",
                outcome="denied",
                document_id=document_id
            )
            db.session.commit()
            abort(403)

        grant = Grant.query.filter_by(
            document_id=doc.id,
            user_id=user_id,
            revoked_at=None
        ).first()

        if grant:
            from .models import utcnow
            grant.revoked_at = utcnow()
            append_audit(
                "permission_revoke",
                document_id=doc.id,
                detail=f"user={user_id}"
            )
        else:
            append_audit(
                "permission_revoke",
                outcome="denied",
                document_id=doc.id,
                detail=f"No active grant for user={user_id}"
            )

        db.session.commit()
        return redirect(url_for("document_detail", document_id=doc.id))
    @app.post("/documents/<int:document_id>/edit")
    @login_required
    def edit_document(document_id):
        doc = db.session.get(Document, document_id)
        if not doc or not can_access(doc, current_user, "edit"):
            append_audit("document_edit", outcome="denied", document_id=document_id)
            db.session.commit()
            abort(403)
        doc.title = request.form.get("title", doc.title).strip()[:180] or doc.title
        doc.category = request.form.get("category", doc.category).strip()[:80] or doc.category
        append_audit("document_edit", document_id=doc.id)
        db.session.commit()
        return redirect(url_for("document_detail", document_id=doc.id))

    @app.post("/documents/<int:document_id>/delete")
    @login_required
    def delete_document(document_id):
        doc = db.session.get(Document, document_id)
        if not doc or doc.owner_id != current_user.id:
            append_audit("document_delete", outcome="denied", document_id=document_id)
            db.session.commit()
            abort(403)
        from .models import utcnow
        doc.deleted_at = utcnow()
        append_audit("document_delete", document_id=doc.id, detail="Soft-deleted")
        db.session.commit()
        return redirect(url_for("dashboard"))
    @app.post("/admin/documents/<int:document_id>/delete")
    @login_required
    def admin_delete_document(document_id):
        if current_user.role != "admin":
            append_audit(
                "document_delete",
                outcome="denied",
                document_id=document_id,
                detail="Non-admin attempted admin deletion"
            )
            db.session.commit()
            abort(403)

        doc = db.session.get(Document, document_id)

        if not doc or doc.deleted_at is not None:
            append_audit(
                "document_delete",
                outcome="denied",
                document_id=document_id,
                detail="Admin deletion target missing or already deleted"
            )
            db.session.commit()
            abort(404)

        from .models import utcnow
        doc.deleted_at = utcnow()

        append_audit(
            "document_delete",
            document_id=doc.id,
            detail="Admin soft-deleted document"
        )

        db.session.commit()
        return redirect(url_for("admin_dashboard"))
    @app.get("/admin")
    @login_required
    def admin_dashboard():
        if current_user.role != "admin":
            append_audit(
                "admin_access",
                outcome="denied",
                detail="Non-admin attempted admin dashboard access"
            )
            db.session.commit()
            abort(403)
        users = User.query.order_by(User.created_at.desc()).all()
        docs = Document.query.order_by(Document.created_at.desc()).all()
        grants = Grant.query.order_by(Grant.created_at.desc()).all()
        events = AuditEvent.query.order_by(AuditEvent.id.desc()).all()
        return render_template("admin.html", users=users, docs=docs, grants=grants, events=events, chain_ok=verify_audit_chain())
    @app.post("/admin/users/<int:user_id>/toggle")
    @login_required
    def toggle_user(user_id):
        if current_user.role != "admin":
            abort(403)
        user = db.session.get(User, user_id)
        if not user or user.id == current_user.id:
            abort(400)
        user.active = not user.active
        append_audit("user_status_changed", detail=f"user={user.id};active={user.active}")
        db.session.commit()
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/users/<int:user_id>/role")
    @login_required
    def change_user_role(user_id):
        if current_user.role != "admin": abort(403)
        user = db.session.get(User, user_id)
        role = request.form.get("role", "")
        if not user or user.id == current_user.id or role not in {"owner", "viewer", "admin"}: abort(400)
        old_role = user.role
        user.role = role
        append_audit("user_role_changed", detail=f"user={user.id};from={old_role};to={role}")
        db.session.commit()
        return redirect(url_for("admin_dashboard"))
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

