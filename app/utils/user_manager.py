from app.utils.models import db, User
from werkzeug.security import generate_password_hash, check_password_hash

class UserManager:
    @staticmethod
    def create_user(username, password, email, is_admin=False):
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw, email=email, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    @staticmethod
    def get_user_by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def verify_password(user, password):
        return check_password_hash(user.password, password)
