from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (db.Index("ix_user_email", "email"),)  # Only if needed for search

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    user_id = db.Column(
        db.String(120), nullable=False, unique=True, default=lambda: str(uuid.uuid4())
    )

    groups = db.Column(db.JSON, default=lambda: ["saml_users"])
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_editable_user_fields():
        exclude = {"id", "user_id", "password_hash", "created_at", "updated_at"}
        fields = [c.name for c in User.__table__.columns if c.name not in exclude]
        fields.append("password")
        return fields


class ServiceProvider(db.Model):
    __tablename__ = "service_providers"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    entity_id = db.Column(db.String(256), nullable=False, unique=True)
    acs_url = db.Column(db.String(512), nullable=False)
    attr_map = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime, default=db.func.now())
