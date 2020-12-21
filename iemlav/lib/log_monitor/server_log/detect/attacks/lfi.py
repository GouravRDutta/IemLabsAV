# -*- coding: utf-8 -*-


from iemlav.lib.log_monitor.server_log.server_logger import ServerLogger
from iemlav.lib.log_monitor.server_log import utils


class LFI(object):
    """LFI Class."""

    def __init__(self, debug=False):

        self.logger = ServerLogger(
            __name__,
            debug=debug
        )

        # Path of file containing lfi payloads
        self.PAYLOAD_FILE = "/home/gourav/Desktop/IEMLAV/iemlav/lib/log_monitor/server_log/rules/payloads/lfi.txt"

        # Load lfi payloads
        self.payloads = utils.open_file(self.PAYLOAD_FILE)

        # Logged IP list
        self.logged_IP = list()

    def detect_lfi(self, data):
        """
        Detect possible Local File Inclusion (lfi) attacks.
        Use string comparison to scan GET request with the
        list of possible LFI payloads.

        Args:
            data (dict): Parsed log file data

        Raises:
            None

        Returns:
            None
        """
        for ip in data.keys():
            get_req = data[ip]["get"]
            if (self.payload_match(get_req)):
                if ip not in self.logged_IP:  # if IP not logged earlier
                    self.logged_IP.append(ip)
                    msg = "Possible LFI injection detected from: " + str(ip) + \
                          " on: " + utils.epoch_to_date(data[ip]["ep_time"][0])
                    self.logger.log(
                        msg,
                        logtype="warning"
                    )
                    utils.write_ip(str(ip))

    def payload_match(self, get_req):
        """
        Match parsed GET request for a
        possible lfi payload.

        Args:
            get_req (str): GET request on which to perform
                           payload string matching

        Raises:
            None

        Returns:
            TYPE: bool
        """
        for req in get_req:
            for payload in self.payloads:
                payload = payload.strip(" ").strip("\n")
                if (payload in req or
                    utils.uri_encode(payload) in req):
                    return True
