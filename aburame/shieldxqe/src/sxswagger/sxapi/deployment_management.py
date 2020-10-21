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
# Deployment Management

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class DeploymentManagement(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URL specific to this Module
        self.dataplane_url = "chassis"

        # URL separator
        self.sep_url = "/"

    def create_deployment(self, deployment_info):
        # Deployment ID
        deployment_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.dataplane_url

        # Headers
        headers = self.rest_session.headers

        # Data
        data = json.dumps(deployment_info)

        # Create Deployment - POST
        response = self.rest_call.post_query(
                       url = url,
                       data = data,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            deployment = dict(response.json())
            deployment_id = deployment["id"]
        else:
            pass

        return deployment_id

    def delete_deployment(self, deployment_id):
        forced = 0

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url +  self.sep_url + str(deployment_id) + self.sep_url + str(forced)

        # Headers
        headers = self.rest_session.headers

        # Delete Deployment - DELETE
        response = self.rest_call.delete_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            return True
        else:
            return False

if __name__ == "__main__":
    pass
