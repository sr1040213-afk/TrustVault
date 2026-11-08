# One-time local admin bootstrap

Register the intended admin account, stop the app, then run this in project root:

```powershell
@'
from app import create_app
from app.extensions import db
from app.models import User
app = create_app()
with app.app_context():
    email = input("Admin email: ").strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        raise SystemExit("Register the account first.")
    user.role = "admin"
    db.session.commit()
    print("Admin role assigned.")
'@ | Set-Content .\bootstrap_admin.py
python .\bootstrap_admin.py
Remove-Item .\bootstrap_admin.py
```
Local development only. Never expose a public role-escalation endpoint.
