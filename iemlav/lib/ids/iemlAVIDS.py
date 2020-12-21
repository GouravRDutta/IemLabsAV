# -*- coding: utf-8 -*-


from iemlav.lib.ids.recon_attack import DetectRecon
from iemlav.lib.ids.r2l_rules.r2l_engine import R2LEngine
from iemlav.lib.firewall.utils import *
from iemlav import logger
import scapy.all as scapy
import sys


class IemlAVIDS(object):
    """IemlAVIDS Class."""

    def __init__(self, cred=None, debug=None):

        self.cred = cred

        # Initialize logger
        self.logger = logger.IemlAVLogger(
                __name__,
                debug=debug
        )

        # Check for root
        if check_root():
            # Create DetectRecon object
            self.recon_obj = DetectRecon(threshold=self.cred["threshold"],
                                         debug=debug)

            interface = self.cred["interface"]
            if interface is not None and interface != "XXXX":
                self.interface = interface
            else:
                self.logger.log(
                    "Collecting interface",
                    logtype="info"
                )
                self.interface = get_interface()

            # Create R2LEngine object
            self.r2l_rules = R2LEngine(debug=debug, interface=self.interface)
            self.logger.log(
                "IemlAV Intrusion Detection started",
                logtype="info"
            )
        else:
            self.logger.log(
                "Run as root",
                logtype="error"
            )
            sys.exit(1)

    def run(self, scapy_pkt):
        """
        Process the packet by passing it through various
        filters.

        - Reconnaissance attacks
        - R2L attacks

        Args:
            scapy_pkt (scapy_object): Packet to dissect and process

        Raises:
            None

        Returns:
            None
        """
        # Process the packet for reconnaissance detection
        self.recon_obj.run(scapy_pkt)
        # Process the packet for R2L attack detection
        self.r2l_rules.run(scapy_pkt)

    def start_ids(self):
        """
        Start IemlAV IDS.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        # Start sniffing the network packets
        scapy.sniff(prn=self.run, store=0)
