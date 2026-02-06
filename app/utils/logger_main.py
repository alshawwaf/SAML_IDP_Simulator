import logging
import os
from logging.handlers import RotatingFileHandler
from app.utils.path_config import LOGS_DIR

def setup_logger():
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
        
    logger = logging.getLogger('idp_simulator')
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    file_handler = RotatingFileHandler(
        LOGS_DIR / 'app.log', maxBytes=10485760, backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()
