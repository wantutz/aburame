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
# Audit Log

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class AuditLog(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URL specific to this Module
        self.audit_log_url = "logs/audit"

    def get_audit_log(self, query=None):
        # Audit Log
        audit_log = []

        # Craft the URL
        url = self.rest_session.base_url + self.audit_log_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - POST
        response = self.rest_call.post_query(
                       url = url,
                       verify = False,
                       headers = headers,
                       data = query
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            audit_log = list(response.json())
        else:
            pass

        return audit_log

if __name__ == "__main__":
    pass
