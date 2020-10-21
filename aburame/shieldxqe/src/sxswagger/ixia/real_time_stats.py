#!/usr/bin/python

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
# Breaking Point - Real Time Stats

# standard library

# 3rd party library

# shieldx library
from sxswagger.common.custom_logger import CustomLogger

class RealTimeStats:
    # Valid Stats Group; default is "summary"
    STATSGROUP = [
        "summary",
        "iface",
        "l4stats",
        "sslStats",
        "ipsecStats",
        "l7Stats",
        "clientStats",
        "attackStats",
        "gtp",
        "resource"
    ]

    SUMMARY = 0
    IFACE = 1
    L4STATS = 2
    SSLSTATS = 3
    IPSECSTATS = 4
    L7STATS = 5
    CLIENTSTATS = 6
    ATTACKSTATS = 7
    GTP = 8
    RESOURCE = 9

    def __init__(self):
        # singleton logger
        self.logger = CustomLogger().get_logger()

    def parse_stats(self, rts_values):
        # RTS Stats
        rts_stats = {}

        # Get values
        if rts_values is not None:
            temp = (rts_values.split("values=")[1]).strip().strip("][").split(" ")

            # Parse values
            for item in temp:
                key, value = item.split("=")
                rts_stats[key] = value.strip("'")
        else:
            pass

        return rts_stats

if __name__ == '__main__':
    pass
