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
#
# Whitelist

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class Whitelist(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs specific to IP Whitelist
        self.whitelist_url = "accesscontrol/whitelistedips"
        self.export_listed_ip_url = "accesscontrol/export/whitelist"

    def get_ip_whitelist(self):
        # Whitelists
        whitelists = None

        # Craft the URL
        url = self.rest_session.base_url + self.whitelist_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Sample: {"cidr": 0, "sumtotal": 0, "ipv4": 0, "ipv6": 0}
        whitelists = dict(response.json())

        return whitelists

    def import_listed_ip(self, whitelist, whitelist_period):
        # Action
        is_imported = False

        # Craft the URL
        url = self.rest_session.base_url + self.whitelist_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps({
                   "whitelistPeriod": whitelist_period,
                   "iplist": [
                       whitelist
                   ]
               })

        # Call REST - POST
        response = self.rest_call.post_query(
                       url = url,
                       verify = False,
                       headers = headers,
                       data = data
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_imported = True
        else:
            is_imported = False

        return is_imported

    def export_listed_ip(self, export_file = None):
        # Action
        is_exported = False
        # IP Whitelist
        ip_whitelist = None

        # Craft the URL
        url = self.rest_session.base_url + self.export_listed_ip_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            ip_whitelist = response.text
            is_exported = True
        else:
            is_exported = False

        try:
            if export_file is not None:
                with open(export_file, "w") as txt_file:
                    txt_file.write(ip_whitelist)
            else:
                self.logger.error("Export file is not specified or export request failed.")
        except Exception as e:
            self.logger.error("Export whitelist failed.")
            self.logger.error(e)

        return is_exported

if __name__ == "__main__":
    # Use Common Test Infra for Func and Unit tests
    pass
