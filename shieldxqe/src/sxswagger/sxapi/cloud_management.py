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
# Cloud Management

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class CloudManagement(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URL specific to this Module
        self.infras_url = "infras"

        # URL separator
        self.sep_url = "/"

    def create_cloud_infra(self, **cloud_info):
        # Infra ID
        infra_id = None

        # Verify necessary info are defined
        try:
            # Verify cloud info is not None
            if not all([cloud_info["cloud_type"],
                        cloud_info["username"],
                        cloud_info["password"],
                   ]):
                self.logger.error("One of the cloud info is None.")
                return infra_id
            else:
                # Proceed with cloud infra creation
                pass
        except KeyError as e:
            self.logger.error("Missing necessary cloud information.")
            return infra_id

        # Verify cloud information
        if cloud_info["cloud_type"] == "VMWARE":
            self.logger.info("Cloud Type: {}".format(cloud_info["cloud_type"]))
        elif cloud_info["cloud_type"] == "AWS":
            self.logger.info("Cloud Type: {}".format(cloud_info["cloud_type"]))
        elif cloud_info["cloud_type"] == "MS Azure":
            self.logger.info("Cloud Type: {}".format(cloud_info["cloud_type"]))
        else:
            self.logger.error("Cloud Type: {}".format(cloud_info["cloud_type"]))

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url

        # Headers
        headers = self.rest_session.headers

        # Create Infra Connector - POST

        # Convert response to expected data

        return infra_id

    def get_cloud_infra(self):
        # Infra ID
        cloud_id_list = None

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url

        # Headers
        headers = self.rest_session.headers

        # Get Cloud Infras - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            cloud_id_list = list(response.json())
        else:
            pass

        return cloud_id_list

if __name__ == "__main__":
    pass
