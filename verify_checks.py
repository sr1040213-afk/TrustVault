from app import create_app
from app.extensions import db
from sqlalchemy import inspect

app = create_app()

with app.app_context():
    inspector = inspect(db.engine)

    for table in ["user", "document", "grant", "audit_event"]:
        checks = inspector.get_check_constraints(table)
        print(f"\n{table}: {len(checks)} CHECK constraints")
        for item in checks:
            print(item["name"], "=>", item["sqltext"])
