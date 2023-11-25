import logging

# Configure access log
access_logger = logging.getLogger('access_logger')
access_logger.setLevel(logging.INFO)
access_handler = logging.FileHandler('access.log')
access_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s'))
access_logger.addHandler(access_handler)

# Configure error log
error_logger = logging.getLogger('error_logger')
error_logger.setLevel(logging.ERROR)
error_handler = logging.FileHandler('error.log')
error_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s]: %(message)s'))
error_logger.addHandler(error_handler)

def log_access_activity(message):
    access_logger.info(message)


def log_error(message):
    error_logger.error(message)