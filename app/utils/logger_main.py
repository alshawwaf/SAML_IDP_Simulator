import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler

def configure_logging() -> logging.Logger:
    """Configure logging system with file rotation and console output"""
    log_dir = Path("logs")
    log_file = log_dir / "saml_idp.log"
    
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise RuntimeError(f"Unable to create logs directory: {str(e)}")

    logger = logging.getLogger("SAML-IDP")
    logger.setLevel(logging.DEBUG)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3,
        encoding='utf-8'
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

log = configure_logging()