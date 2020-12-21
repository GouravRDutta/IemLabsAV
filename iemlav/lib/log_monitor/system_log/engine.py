# -*- coding: utf-8 -*-

from iemlav.lib.log_monitor.system_log import failed_login
from iemlav.lib.log_monitor.system_log import harmful_root_command
from iemlav.lib.log_monitor.system_log import detect_backdoor
from iemlav.lib.log_monitor.system_log import password_defect
from iemlav.lib.log_monitor.system_log import check_sync
from iemlav.lib.log_monitor.system_log import port_scan
from iemlav.lib.log_monitor.system_log import ssh_login
from iemlav.lib.log_monitor.system_log import detect_sniffer
from iemlav.lib.log_monitor.system_log import non_std_hash
from iemlav.lib.log_monitor.system_log import utils
from iemlav import logger
import sys


class SystemLogEngine(object):
    """SystemLogEngine Class."""

    def __init__(self, debug=False):
        """
        Initialize SystemLogEngine.

        Args:
            debug (bool): Log on terminal or not

        Raises:
            None

        Returns:
            None
        """
        # Initialize logger
        self.logger = logger.IemlAVLogger(
                __name__,
                debug=debug
        )

        # Check if running as root or not
        if utils.check_root():
            # Create module objects
            self.failed_login_obj = failed_login.FailedLogin(debug=debug)
            self.harmful_command = harmful_root_command.HarmfulCommands(debug=debug)
            self.detect_backdoor = detect_backdoor.DetectBackdoor(debug=debug)
            self.checksync = check_sync.CheckSync(debug=debug)
            self.password_def = password_defect.PasswordDefect(debug=debug)
            self.portscan = port_scan.PortScan(debug=debug)
            self.sshlogin = ssh_login.SSHLogin(debug=debug)
            self.detsniffer = detect_sniffer.DetSniffer(debug=debug)
            self.non_std = non_std_hash.NonStdHash(debug=debug)
        else:
            self.logger.log(
                "Please run as root, exiting.",
                logtype="error"
            )
            sys.exit(0)

    def run(self):
        """
        Start the system log monitoring process.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        try:
            while True:
                # Monitor failed login attempts & brute-force
                self.failed_login_obj.run()
                # Monitor harmful commands executed as root
                self.harmful_command.run()
                # Monitor for backdoors
                self.detect_backdoor.run()
                # Check for sync
                self.checksync.run()
                # Check for password defects
                self.password_def.run()
                # Check for port scans
                self.portscan.run()
                # Check for failed SSH login
                self.sshlogin.run()
                # Check for malicious sniffer
                self.detsniffer.run()
                # Check for deviating hash algorithm
                self.non_std.run()
        except KeyboardInterrupt:
            self.logger.log(
                "KeyboardInterrupt detected, ending monitoring",
                logtype="info"
            )
