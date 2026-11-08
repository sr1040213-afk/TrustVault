from app import create_app
from app.extensions import db
from sqlalchemy import inspect, text

app = create_app()

with app.app_context():
    inspector = inspect(db.engine)

    print("=== CHECK CONSTRAINTS ===")
    for table in ["user", "document", "grant", "audit_event"]:
        checks = inspector.get_check_constraints(table)
        print(f"\n{table}:")
        for check in checks:
            print(" ", check["name"], ":", check["sqltext"])

    print("\n=== RECORD COUNTS ===")
    with db.engine.connect() as conn:
        for table in ["user", "document", "grant", "audit_event"]:
            count = conn.execute(
                text(f"SELECT COUNT(*) FROM {table}")
            ).scalar()
            print(table, count)

        print("\n=== FOREIGN KEY CHECK ===")
        violations = conn.execute(
            text("PRAGMA foreign_key_check")
        ).fetchall()
        print("Violations:", violations)
