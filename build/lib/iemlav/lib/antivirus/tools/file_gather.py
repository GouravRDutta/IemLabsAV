
from iemlav.lib.antivirus.antivirus_logger import AntiVirusLogger

import os


class GatherFile(object):
    """GatherFile class."""

    def __init__(self, debug=False, path=None):

        # Initialize logger
        self.logger = AntiVirusLogger(
                __name__,
                debug=debug
        )

        # Initialize path of directory to look for
        self._PATH = path

    def scan_dir(self):

        found_files = []  # Initialize empty list of found files

        try:
            # Iterate through the directory
            for root, _, files in os.walk(self._PATH):
                for file in files:
                    found_files.append(os.path.join(root, file))
        except Exception as e:
            self.logger.log(
                "Error occurred: " + str(e),
                logtype="error"
            )

        # Return the list of found files
        return found_files
