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
# Policy Management
#     SecurityPolicySets

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class SecurityPolicySets(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs - Security Policy Set
        self.sps_url = "policy/securitypolicyset"
        self.sps_by_tenant_id_url = "policy/securitypolicyset/tenant/{tenant_id}"
        self.sps_by_id_url = "policy/securitypolicyset/{sps_id}"

    def create_security_policy_set(self, policy):
        # Security Policy Set ID
        policy_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.sps_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(policy)

        # Create SPS - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policy_id = int(response.text)
        else:
            pass

        return policy_id

    def update_security_policy_set(self, policy):
        # Security Policy Set ID
        policy_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.sps_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(policy)

        # Update SPS - PUT
        response = self.rest_call.put_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policy_id = int(response.text)
        else:
            pass

        return policy_id

    def get_security_policy_set(self):
        # Security Policy Set List
        sps_list = []

        # Craft the URL
        url = self.rest_session.base_url + self.sps_url

        # Headers
        headers = self.rest_session.headers

        # Get SPS List - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            sps_list = list(response.json())
        else:
            # Empty list
            pass

        return sps_list

    def get_sps_by_id(self, sps_id):
        # Security Policy Set
        sps = None

        # Craft the URL
        url = self.rest_session.base_url + self.sps_by_id_url.format(sps_id=sps_id)

        # Headers
        headers = self.rest_session.headers

        # Get SPS - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            sps = dict(response.json())
        else:
            # Empty list
            pass

        return sps

    def get_sps_by_name(self, sps_name):
        # Security Policy Set
        sps = None

        # Get list of SPS
        sps_list = self.get_security_policy_set()

        # Find the index of the SPS
        sps_names = [sps["name"] for sps in sps_list]

        if sps_name in sps_names:
            index = sps_names.index(sps_name)
            sps = sps_list[index]
        else:
            # SPS not found
            pass

        return sps

    def delete_security_policy_set_by_id(self, sps_id):
        # Action
        is_deleted = False

        # Craft the URL
        url = self.rest_session.base_url + self.sps_by_id_url.format(sps_id=sps_id)

        # Headers
        headers = self.rest_session.headers

        # Delete Security Policy Set by ID
        response = self.rest_call.delete_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_deleted = True
        else:
            # Empty list
            pass

        return is_deleted

if __name__ == "__main__":
    pass
