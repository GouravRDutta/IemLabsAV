

import os
import sys

from iemlav.lib.antivirus.tools import utils
from iemlav.lib.antivirus.antivirus_logger import AntiVirusLogger


class Cleaner(object):
    """Cleaner class."""

    def __init__(self, debug=False, config_path=None):
        
        self.logger = AntiVirusLogger(
                __name__,
                debug=debug
        )

        if config_path:
            self._CONFIG_PATH = config_path
        else:
            self.logger.log(
                "Configuration file not found",
                logtype="error"
            )
            sys.exit(0)

        # Load Configuration
        self.config_dict = utils.json_to_dict(self._CONFIG_PATH)
        # Categorize OS
        self.os_name = utils.categorize_os()
        if self.os_name:
            # Load malicious-file log path
            self._MAL_FILE_PATH = self.config_dict[self.os_name]["scanner"]["malicious_file_log_path"]

    def clean(self):
        
        # List of malicious files detected
        print("\n[!] List of possible malicious files found: ")
        try:
            self.malicious_file_list = [file_path.strip("\n") \
                                        for file_path in utils.open_file(self._MAL_FILE_PATH)]
        except FileNotFoundError:
            # Initialize empty list
            self.malicious_file_list = list()

        for index, mal_file in enumerate(self.malicious_file_list):
            print("[{0}] {1}".format(index, mal_file))

        to_clean = input("Enter the index of the file to delete ('e' to exit): ")
        if to_clean == "e":
            return
        else:
            to_clean = int(to_clean)
            file_path = self.malicious_file_list[to_clean]
            print("Removing: ", file_path)
            try:
                os.remove(file_path)
                self.malicious_file_list.remove(file_path)
            except FileNotFoundError:
                pass
            except Exception as e:
                self.logger.log(
                    "Error occurred: " + str(e),
                    logtype="error"
                )
            with open(self._MAL_FILE_PATH, "w") as wf:
                for mal_file in self.malicious_file_list:
                    wf.write(mal_file)
            self.clean()

    def auto_delete(self):
        
        self.logger.log(
            "Auto-cleaning the malicious files",
            logtype="info"
        )
        print("[!] Auto-cleaning the malicious files")
        try:
            self.malicious_file_list = [file_path.strip("\n") \
                                        for file_path in utils.open_file(self._MAL_FILE_PATH)]
        except FileNotFoundError:
            # Initialize empty list
            self.malicious_file_list = list()
        for mal_file in self.malicious_file_list:
            try:
                os.remove(mal_file)
                self.logger.log(
                    "Removing: " + mal_file,
                    logtype="info"
                )
                self.malicious_file_list.remove(mal_file)
            except FileNotFoundError:
                pass
            except Exception as e:
                self.logger.log(
                    "Error occurred: " + str(e),
                    logtype="error"
                )
        with open(self._MAL_FILE_PATH, "w") as wf:
            for mal_file in self.malicious_file_list:
                wf.write(mal_file)
