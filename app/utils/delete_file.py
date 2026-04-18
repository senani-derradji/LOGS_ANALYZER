import os
from pathlib import Path


def delete_file(file_path: Path | str) -> bool:

    if isinstance(file_path, str): file_path = Path(file_path)

    try:
        if os.path.exists(file_path):
            if os.remove(file_path):
                print(f"File '{file_path}' has been deleted.") ; return True
        else:
            print(f"File '{file_path}' does not exist.") ; return False
    except Exception as e:
        print(f"Error deleting file '{file_path}': {e}") ; return False