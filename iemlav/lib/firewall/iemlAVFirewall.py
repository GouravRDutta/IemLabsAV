# -*- coding: utf-8 -*-

from iemlav.lib.firewall.engine import FirewallEngine
from iemlav.lib.firewall.utils import check_root
from iemlav import logger
import sys


class IemlAVFirewall(object):
    """IemlAVFirewall Class."""

    def __init__(self, cred=None, debug=None):
        """Initialize IemlAVFirewall."""

        self.cred = cred['firewall']
        self.debug = cred['debug']
        self.logger = logger.IemlAVLogger(
                __name__,
                debug=self.debug
            )

    def start_firewall(self):
        """
        Start firewall engine.
        """
        if check_root():
            engineObj = FirewallEngine(cred=self.cred,
                                       debug=self.debug)
            engineObj.startEngine()
            self.logger.log(
                "Firewall started",
                logtype="info"
            )
        else:
            self.logger.log(
                "Run as root",
                logtype="error"
            )
            sys.exit(1)
