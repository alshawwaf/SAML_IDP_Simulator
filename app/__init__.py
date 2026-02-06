from flask import Flask
from flask_wtf.csrf import CSRFProtect
from app.utils.models import db, User, ServiceProvider
from app.utils.config_manager import config_manager
from app.utils.logger_main import logger
import uuid

csrf = CSRFProtect()

def seed_default_data():
    """Create default users and service providers if database is empty"""
    
    # Default SAML Users for Check Point demos
    default_users = [
        {
            "username": "demo.user",
            "email": "demo.user@cpdemo.ca",
            "password": "Cpwins!1@2026",
            "first_name": "Demo",
            "last_name": "User",
            "groups": ["saml_users", "vpn_users"],
        },
        {
            "username": "john.smith",
            "email": "john.smith@cpdemo.ca",
            "password": "Cpwins!1@2026",
            "first_name": "John",
            "last_name": "Smith",
            "groups": ["saml_users", "admins"],
        },
        {
            "username": "jane.doe",
            "email": "jane.doe@cpdemo.ca",
            "password": "Cpwins!1@2026",
            "first_name": "Jane",
            "last_name": "Doe",
            "groups": ["saml_users", "security_admins"],
        },
    ]
    
    # Default Service Providers for Check Point products
    default_sps = [
        {
            "name": "Harmony Connect Portal",
            "entity_id": "https://10.1.1.111/connect/spPortal/ACS/ID/4bd3c39d-3f85-444f-9230-92c922b93db4",
            "acs_url": "https://10.1.1.111/connect/spPortal/ACS/Login/4bd3c39d-3f85-444f-9230-92c922b93db4",
            "attr_map": [
                {"claim": "email", "value": "email"},
                {"claim": "firstName", "value": "first_name"},
                {"claim": "lastName", "value": "last_name"},
                {"claim": "groups", "value": "groups"},
            ],
        },
        {
            "name": "Quantum Security Gateway",
            "entity_id": "https://gateway.cpdemo.local/saml/sp",
            "acs_url": "https://gateway.cpdemo.local/saml/acs",
            "attr_map": [
                {"claim": "email", "value": "email"},
                {"claim": "uid", "value": "username"},
                {"claim": "groups", "value": "groups"},
            ],
        },
        {
            "name": "SmartConsole",
            "entity_id": "https://smartconsole.cpdemo.local/saml/metadata",
            "acs_url": "https://smartconsole.cpdemo.local/saml/acs",
            "attr_map": [
                {"claim": "email", "value": "email"},
                {"claim": "name", "value": "first_name"},
                {"claim": "surname", "value": "last_name"},
                {"claim": "role", "value": "groups"},
            ],
        },
    ]
    
    # Create default users if none exist
    if User.query.count() == 0:
        logger.info("Creating default demo users...")
        for user_data in default_users:
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                first_name=user_data["first_name"],
                last_name=user_data["last_name"],
                groups=user_data["groups"],
                user_id=str(uuid.uuid4()),
            )
            user.set_password(user_data["password"])
            db.session.add(user)
        db.session.commit()
        logger.info(f"Created {len(default_users)} default users")
    
    # Create default service providers if none exist
    if ServiceProvider.query.count() == 0:
        logger.info("Creating default service providers...")
        for sp_data in default_sps:
            sp = ServiceProvider(
                name=sp_data["name"],
                entity_id=sp_data["entity_id"],
                acs_url=sp_data["acs_url"],
                attr_map=sp_data["attr_map"],
            )
            db.session.add(sp)
        db.session.commit()
        logger.info(f"Created {len(default_sps)} default service providers")


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = config_manager.SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    csrf.init_app(app)

    with app.app_context():
        from app.routes.metadata import metadata_bp
        from app.routes.auth import auth_bp
        from app.routes.admin import admin_bp
        
        app.register_blueprint(metadata_bp)
        app.register_blueprint(auth_bp)
        app.register_blueprint(admin_bp)
        
        db.create_all()
        seed_default_data()
        logger.info("Application initialized and database created.")

    return app
