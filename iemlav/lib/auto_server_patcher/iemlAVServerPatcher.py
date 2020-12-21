
import sys
from iemlav.lib.auto_server_patcher.ssl_scanner import SSLScanner
from iemlav.lib.auto_server_patcher.installer import Installer
from iemlav.lib.auto_server_patcher.patcher import ConfigPatcher
from iemlav.lib.auto_server_patcher.patch_logger import PatchLogger
from iemlav.lib.auto_server_patcher import utils


class IemlAVAutoServerPatcher(object):
    """IemlAVAutoServerPatcher Class."""

    def __init__(self, debug=False, cred=None):

        # Initialize logger
        self.logger = PatchLogger(
            __name__,
            debug=debug
        )

        if not utils.check_root():
            self.logger.log(
                "Please run as root, exiting.",
                logtype="error"
            )
            sys.exit(0)

        if not cred:
            self.logger.log(
                "No credentials specified.",
                logtype="error"
            )
            sys.exit(0)

        # List of files to patch
        self.to_patch = list()

        url = cred['url']
        apache = int(cred['apache'])
        ssh = int(cred['ssh'])
        login = int(cred['login'])
        sysctl = int(cred['sysctl'])

        # Determine which file to patch
        if apache == 1:
            self.to_patch.append("apache")
        if ssh == 1:
            self.to_patch.append("ssh")
        if login == 1:
            self.to_patch.append("login")
        if sysctl == 1:
            self.to_patch.append("sysctl")

        if url and url != "XXXX":  # if valid URL
            self.url = url
        else:
            self.url = None

        # Create Installer object
        self.installer = Installer(debug=debug)
        # Create Patcher object
        self.patcher = ConfigPatcher(debug=debug, to_patch=self.to_patch)
        if self.url:
            # Create SSLScanner object
            self.ssl_scanner = SSLScanner(debug=debug, url=self.url)

    def start(self):
        
        self.patcher.patch()
        # Start executing configuraton commands
        self.installer.install()
        if self.url:  # if url is provided
            # Start SSL scanning
            self.ssl_scanner.start_scan()
