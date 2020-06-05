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

class ThreatEncyclopedia(object):
    """ Test Data """

    # Take this data from a database for a more comprehensive test
    rules = [
        {
            "pm_id": "1",
            "rule_id": "2514",
            "name": "D-Link Authorization HTTP Header Buffer Overflow",
            "pcaps": [
                "/mnt/content/Drop/BreakingPoint/PCAPS_2018_C2S_and_S2C_12_20_2018/StrikeLevel_c2s/strikes/exploits/webapp/exec/cve_2018_15839_dlink_dir_authorization_header_bof.xml/Slot1Port3Hostnp1%2d0.1545368793135.pcap"
            ],
        },
        {
            "pm_id": "1",
            "rule_id": "1988",
            "name": "Squid Range Header Denial of Service"
        },
        {
            "pm_id": "1",
            "rule_id": "10349",
            "name": "ACME mini_httpd Arbitrary File Read",
            "strike_id": "E18-5od61",
            "direction": "c2s",
            "cve_id": "CVE-2018-18778"
        },
        {
            "pm_id": "1",
            "rule_id": "5075",
            "name": "Apache Tomcat CVE-2019-0232 Remote Code Execution Vulnerability",
            "strike_id": "E19-0qvs1",
            "direction": "c2s",
            "cve_id": "CVE-2019-0232"
        },
        {
            "pm_id": "1",
            "rule_id": "5128",
            "name": "Cisco RV320 VPN Router Authenticated Command Injection",
            "strike_id": "E19-0rz81",
            "direction": "c2s",
            "cve_id": "CVE-2019-1652"
        },
    ]

    def __init__(self):
        pass

if __name__ == "__main__":
    pass
