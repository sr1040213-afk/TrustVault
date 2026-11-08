from app import create_app
from app.extensions import db
from app.models import User, Document, Grant, AuditEvent
from app.security import verify_audit_chain
from sqlalchemy import inspect, text

app = create_app()

with app.app_context():
    print("DATABASE:", app.config["SQLALCHEMY_DATABASE_URI"])

    print("\n=== RECORD COUNTS ===")
    print("Users:", User.query.count())
    print("Documents:", Document.query.count())
    print("Grants:", Grant.query.count())
    print("Audit Events:", AuditEvent.query.count())

    print("\n=== DATABASE CONSTRAINTS ===")
    inspector = inspect(db.engine)
    for table in ["user", "document", "grant", "audit_event"]:
        checks = inspector.get_check_constraints(table)
        print(f"{table}: {len(checks)} CHECK constraints")
        for check in checks:
            print("  ", check["name"], "=>", check["sqltext"])

    print("\n=== FOREIGN KEY CHECK ===")
    result = db.session.execute(text("PRAGMA foreign_key_check")).fetchall()
    print("Violations:", result)

    print("\n=== AUDIT CHAIN ===")
    print("AUDIT CHAIN VALID:", verify_audit_chain())
