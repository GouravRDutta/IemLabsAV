
from iemlav.lib.antivirus.scanner.scanner_parent import Scanner

import sys

clamd_status = 1
try:
    import clamd
except ImportError:
    clamd_status = 0
    print("[-] Clamd not installed")


class ClamAVScanner(Scanner):
    """ClamAVScanner class."""

    def __init__(self, debug=False, config_path=None, file_list=None, vt_api_key=None):

        # Initialize parent class
        super().__init__(debug, config_path, file_list, vt_api_key)

        if self.os_name:
            try:
                # Load threads
                self._WORKERS = self.config_dict[self.os_name]["scanner"]["clamav"]["threads"]
            except KeyError:
                self.logger.log(
                    "Could not load configuration for: {}".format(self.os_name),
                    logtype="error"
                )
                sys.exit(0)
        else:
            self.logger.log(
                "Could not determine the OS",
                logtype="error"
            )
            sys.exit(0)

        # Setup Clam AV object
        self.clamd_client = clamd.ClamdUnixSocket()

    def scan_file(self, file_path):


        if clamd_status:
            # Scan file
            scan_res = self.clamd_client.scan(file_path)
            result = scan_res[file_path][0]
            result = result.lower().strip()

            if "found" in result:
                self.logger.log(
                    "Possible malicious file detected: {0}".format(file_path),
                    logtype="warning"
                )
                if file_path not in self.malicious_file_list:
                    self.malicious_file_list.append(file_path)
                    super().check_virus_total(file_path)
                    return
                return
