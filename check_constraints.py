from app import create_app
from app.extensions import db
from sqlalchemy import text

app = create_app()

with app.app_context():
    checks = {
        "invalid_roles": "SELECT COUNT(*) FROM user WHERE role NOT IN ('admin','owner','viewer')",
        "invalid_sizes": "SELECT COUNT(*) FROM document WHERE size < 0",
        "invalid_hashes": "SELECT COUNT(*) FROM document WHERE length(sha256) != 64",
        "invalid_permissions": "SELECT COUNT(*) FROM grant WHERE permission NOT IN ('read','edit')",
        "invalid_outcomes": "SELECT COUNT(*) FROM audit_event WHERE outcome NOT IN ('success','denied','error','integrity_failure')",
        "invalid_previous_mac": "SELECT COUNT(*) FROM audit_event WHERE length(previous_mac) != 64",
        "invalid_event_mac": "SELECT COUNT(*) FROM audit_event WHERE length(event_mac) != 64",
    }

    for name, query in checks.items():
        print(name, db.session.execute(text(query)).scalar())
