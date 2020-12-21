
from iemlav.lib.antivirus.monitor.monitor_changes import MonitorChanges
from iemlav.lib.antivirus.monitor.usb_monitor import USBMonitor
from iemlav.lib.antivirus.antivirus_logger import AntiVirusLogger
from iemlav.lib.antivirus.tools import utils

import multiprocessing
import sys


class MonitorEngine(object):
    """
    MonitorEngine class.
    """

    def __init__(self,
                 debug=False,
                 config_path=None,
                 vt_api_key=None,
                 monitor_changes=1,
                 monitor_usb=1):

        self.debug = debug

        # Initialize logger
        self.logger = AntiVirusLogger(
                __name__,
                debug=self.debug
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
            self.changes_min_time = int(self.config_dict[self.os_name]["monitor"]["threshold_min"])

        self.monitor_changes = int(monitor_changes)
        self.monitor_usb = int(monitor_usb)

        # Create a pool of process
        self.process_pool = []
        # Initialize VirusTotal API key
        self.vt_api_key = vt_api_key

    def kill_process(self):

        for process in self.process_pool:
            process.terminate()

    def create_process(self):

        if self.monitor_changes:
            # Create MonitorChanges object
            self.monitor_changes_obj = MonitorChanges(debug=self.debug,
                                                      config_path=self._CONFIG_PATH,
                                                      min_time=self.changes_min_time,
                                                      vt_api_key=self.vt_api_key)
            monitor_changes_process = multiprocessing.Process(target=self.monitor_changes_obj.monitor)
            # Add to process pool
            self.process_pool.append(monitor_changes_process)

        if self.monitor_usb:
            # Create USBMonitor object
            self.monitor_usb_obj = USBMonitor(debug=self.debug,
                                              config_path=self._CONFIG_PATH,
                                              vt_api_key=self.vt_api_key)
            monitor_usb_process = multiprocessing.Process(target=self.monitor_usb_obj.monitor_usb_device)
            # Add to process pool
            self.process_pool.append(monitor_usb_process)

    def start_monitor_engine(self):

        # Create process based on user choice
        self.create_process()
        try:
            if self.process_pool:
                for process in self.process_pool:
                    process.start()

                for process in self.process_pool:
                    process.join()

        except KeyboardInterrupt:
            self.logger.log(
                "KeyboardInterrupt detected, quitting monitor engine",
                logtype="info"
            )
            # Kill running process
            self.kill_process()

        except Exception as e:
            self.logger.log(
                "Error occurred: " + str(e),
                logtype="error"
            )
            # Kill running process
            self.kill_process()
