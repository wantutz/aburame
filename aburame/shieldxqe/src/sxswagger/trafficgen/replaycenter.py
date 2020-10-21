#/*
#* ShieldX Networks Inc. CONFIDENTIAL
#* ----------------------------------
#*
#* Copyright (c) 2016 ShieldX Networks Inc.
#* All Rights Reserved.
#*
#* NOTICE:  All information contained herein is, and remains
#* the property of ShieldX Networks Incorporated and its suppliers,
#* if any.  The intellectual and technical concepts contained
#* herein are proprietary to ShieldX Networks Incorporated
#* and its suppliers and may be covered by U.S. and Foreign Patents,
#* patents in process, and are protected by trade secret or copyright law.
#* Dissemination of this information or reproduction of this material
#* is strictly forbidden unless prior written permission is obtained
#* from ShieldX Networks Incorporated.
#*/

# Author: Juan

# Data:
#   config (replay interface, mtu, etc.)
# Method:
#   replay(bundle)
#

# 3rd party
from dotmap import DotMap
from scapy.all import *
from scapy.utils import rdpcap

# shieldx library
from sxswagger.common.custom_logger import CustomLogger

class Replaycenter:
    def __init__(self, interface=None):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # error codes
        self.codes = DotMap()
        self.codes.ok = 0
        self.codes.error = -1
        self.codes.missing_iface = -2
        self.codes.missing_pcap = -3

        if interface is not None:
            self.interface = interface
        else:
            pass

    def replay(self, bundle, interface="eth1", inter_pkt_delay=0):
        replay_status = None

        # Check if interface is provided
        if self.interface is None:
            self.logger.error("Replay interface must be provided.")

            return self.codes.missing_iface
        else:
            pass

        # Check if pcaps are provided
        if "pcaps" not in bundle:
            self.logger.warning("Pcaps not found, skipping.")

            return self.codes.missing_pcap
        else:
            pass

        # Replay pcap after done with checks
        pcaps = bundle["pcaps"]

        for pcap in pcaps:
            self.logger.info("Replay Pcap: {}".format(pcap))
            if os.path.isfile(pcap):
                try:
                    pkts = rdpcap(pcap)

                    for pkt in pkts:
                        sendp(pkt, verbose=False, iface=interface, inter=inter_pkt_delay)

                except Exception as e:
                    self.logger.error(e)
                    replay_status = self.codes.error

            # Done replaying pcaps without error
            replay_status = self.codes.ok

        return replay_status

if __name__ == "__main__":
    # Use Common Test Infra for Func and Unit tests
    pass
