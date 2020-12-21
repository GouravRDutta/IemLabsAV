
from pathlib import Path
import os


def check_dir(path):

    try:
        if not os.path.isdir(path):
            Path(path).mkdir()
    except FileExistsError:
        os.remove(path)  # remove file to create directory
        check_dir(path)  # recursively check for any other file
    except FileNotFoundError:
        # Create directory recursively
        new_path = "/".join(path.split("/")[:-1])
        check_dir(path=new_path)
        check_dir(path=path)
