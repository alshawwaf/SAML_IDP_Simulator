from app.utils.models import db, User


class UserManager:
    @staticmethod
    def create_user(username, password, email, is_admin=False):
        # Route through the User model's set_password() so the hash lands in
        # the actual column (`password_hash`). Passing `password=...` as a
        # constructor kwarg crashes because there's no such column.
        new_user = User(username=username, email=email, is_admin=is_admin)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    @staticmethod
    def get_user_by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def verify_password(user, password):
        # The User model exposes check_password() which reads `password_hash`.
        # Touching `user.password` directly raises AttributeError (no such column).
        return user.check_password(password)
