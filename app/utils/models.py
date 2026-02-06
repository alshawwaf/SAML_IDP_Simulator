from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False, default='')
    last_name = db.Column(db.String(80), nullable=False, default='')
    user_id = db.Column(db.String(120), nullable=False, unique=True, default=lambda: str(uuid.uuid4()))
    groups = db.Column(db.JSON, default=lambda: ["saml_users"])
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
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
    id = db.Column(db.Integer, primary_key=True)
    entity_id = db.Column(db.String(255), unique=True, nullable=False)
    acs_url = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    attr_map = db.Column(db.JSON, nullable=False, default=list)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
