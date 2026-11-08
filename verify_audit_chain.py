from app import create_app
from app.security import verify_audit_chain
from app.extensions import db
from app.models import AuditEvent

app = create_app()

with app.app_context():
    count = AuditEvent.query.count()
    result = verify_audit_chain()

    print("AUDIT EVENT COUNT:", count)
    print("AUDIT CHAIN VALID:", result)
