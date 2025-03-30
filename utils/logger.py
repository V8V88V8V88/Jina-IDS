import logging
import colorlog
import os

def setup_logger(log_file="logs/ids.log", debug=False):
    """Set up a color logger."""
    log_dir = os.path.dirname(log_file)
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("JinaLogger")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    formatter = colorlog.ColoredFormatter(
        "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        },
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
