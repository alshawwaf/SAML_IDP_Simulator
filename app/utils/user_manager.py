from app.utils.models import db, User
from werkzeug.security import check_password_hash, generate_password_hash
import re
from app.utils.logger_main import log


class UserManager:
    @staticmethod
    def add_user(username, password, email, groups):
        existing = User.query.filter_by(username=username).first()
        if existing:
            raise ValueError("User exists")
        UserManager.validate_password_complexity(password)
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            email=email,
            groups=groups,
        )
        db.session.add(new_user)
        db.session.commit()

    @staticmethod
    def update_user(username: str, **kwargs):
        user = User.query.filter_by(username=username).first()
        if not user:
            raise ValueError("User not found")

        # Handle password update
        if "password" in kwargs:
            user.set_password(kwargs.pop("password"))
            UserManager.validate_password_complexity(kwargs["password"])

        # Handle groups update
        if "groups" in kwargs:
            kwargs["groups"] = kwargs["groups"]  # Keep as list

        for key, value in kwargs.items():
            setattr(user, key, value)

        db.session.commit()

    @staticmethod
    def get_user(username: str) -> User:
        return User.query.filter_by(username=username).first()

    @staticmethod
    def delete_user(username: str):
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()

    @classmethod
    def validate_user(cls, username, password):
        log.debug(username)
        log.debug(password)
        user = User.query.filter_by(username=username).first()
        log.debug(user.password_hash)
        log.debug(user.username)
        if not user or not check_password_hash(user.password_hash, password):
            return None  # Invalid credentials

        # Return necessary SAML attributes
        return {
            "username": user.username,
            "email": user.email,  # SP might expect email as UserID
            "groups": user.groups,
        }

    @staticmethod
    def validate_password_complexity(password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must contain uppercase letters")
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must contain lowercase letters")
        if not re.search(r"[0-9]", password):
            raise ValueError("Password must contain numbers")
