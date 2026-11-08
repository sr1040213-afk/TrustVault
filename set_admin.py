
from app import create_app
from app.models import User
from app.extensions import db

app = create_app()

with app.app_context():
    email = input("Enter admin account email: ").strip().lower()
    user = User.query.filter_by(email=email).first()

    if user is None:
        print("User not found")
    else:
        user.role = "admin"
        db.session.commit()
        print(f"Success: {user.email} is now Admin")
