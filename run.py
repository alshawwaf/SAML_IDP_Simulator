from app import create_app
from app.utils.config_manager import config_manager

app = create_app()

if __name__ == "__main__":
    app.run(
        host=config_manager.HOST,
        port=config_manager.PORT,
        debug=config_manager.DEBUG
    )
