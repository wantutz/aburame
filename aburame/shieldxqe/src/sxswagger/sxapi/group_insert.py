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

# Author: tony
#
# group and insert

# standard library
import os
import time
import sys
import logging
from contextlib import closing

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall


class GroupandInsert(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # fetched data
        self.data = None

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs specific to Resource group and Network set
        self.resource_group_create_url = "infras/resourcegroup"
        self.network_set_create_url = "infras/networkset"

    def rgany_vmname_noinsertion(self,rname,regexpr,descrip):
        rg_created = False
        rgid = None

        payload = [{
            "infraIDs": [
                0
            ],
            "dynamic": True,
            "id": 0,
            "name": "RG-WL-2",
            "regex": "name='tony-frog-WL-4';",
            "resourceType": "VM",
            "description": "RG-2",
            "purpose": "INSERTION_AND_POLICY"
        }]
        for i in payload:
            if i["infraIDs"] == [0]:
                i["name"] = rname
                i["regex"] = regexpr
                i["description"] = descrip
                data = json.dumps(payload)
                data = str(data)[1:-1]
        try:
            # Craft the URL
            url = self.rest_session.base_url + self.resource_group_create_url

            # Headers
            headers = self.rest_session.headers

            # Call REST - POST
            response = self.rest_call.post_query(
            url=url,
            headers=headers,
            verify=False,
            data=data
        )
            if response.status_code == requests.codes.ok:
                rgid = list(response.json())
                rgid = rgid[0]
                rg_created = True
                self.logger.info("New resource group added")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return rgid

    def nset_create_noinsertion(self,rname,regexpr,descrip):
        ns_created = False
        nsid = None

        payload = [{
            "cloudId":1,
            "id":0,
            "name":"NSET-1-PG63-2",
            "regex":"ic='1';.*name='tony-PG63-2';",
            "description":"NSET-1-PG63-2",
            "isExclusion":False
        }]

        for i in payload:
            if i["cloudId"] == 1:
                i["name"] = rname
                i["regex"] = regexpr
                i["description"] = descrip
                data = json.dumps(payload)
                data = str(data)[1:-1]
        try:
            # Craft the URL
            url = self.rest_session.base_url + self.network_set_create_url

            # Headers
            headers = self.rest_session.headers

            # Call REST - POST
            response = self.rest_call.post_query(
            url=url,
            headers=headers,
            verify=False,
            data=data
        )
            if response.status_code == requests.codes.ok:
                nsid = list(response.json())
                nsid = nsid[0]
                ns_created = True
                self.logger.info("New network set added")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return nsid

if __name__ == "__main__":
    pass
