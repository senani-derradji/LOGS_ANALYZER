import logging
import logging.config
from logging.handlers import RotatingFileHandler
import os


def setup_logging(log_level: str = "INFO", log_dir: str = "logs_anz"):
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "logs_analyzer.log")

    LOGGING_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,

        "formatters": {
            "standard": {
                "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            },
        },

        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": log_level,
                "formatter": "standard",
            },

            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": log_level,
                "formatter": "standard",
                "filename": log_file,
                "maxBytes": 5 * 1024 * 1024,  # 5MB
                "backupCount": 3,
                "encoding": "utf-8",
            },
        },

        "loggers": {
            "": {  # root logger
                "handlers": ["console", "file"],
                "level": log_level,
                "propagate": False,
            },
        }
    }

    logging.config.dictConfig(LOGGING_CONFIG)


# Call this ONCE at app startup
setup_logging()

# Usage anywhere in your project
logger = logging.getLogger(__name__)

logger.info("System started")
logger.warning("This is a warning")
logger.error("Something failed")