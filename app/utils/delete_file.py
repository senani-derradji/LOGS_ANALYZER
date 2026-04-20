import os
from pathlib import Path
from app.utils.logger import logger


def delete_file(file_path: Path | str) -> bool:

    if isinstance(file_path, str): file_path = Path(file_path)

    try:
        if os.path.exists(file_path):
            if os.remove(file_path):
                logger.info(f"File '{file_path}' has been deleted.") ; return True
        else:
            logger.warning(f"File '{file_path}' does not exist.") ; return False
    except Exception as e:
        logger.error(f"Error deleting file '{file_path}': {e}") ; return False