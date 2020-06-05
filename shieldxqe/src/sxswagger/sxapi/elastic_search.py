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

# Elastic Search
#

# standard library

# 3rd party library
import json
import requests
import time

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class ElasticSearch(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URL specific to this Module
        self.nodes_info_url = "sxquery/_nodes"
        self.multi_search_url = "sxquery/_msearch"

        # Spare separator
        self.sep_url = "/"

    def get_nodes_info(self):
        # Nodes Info
        nodes_info = None

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.nodes_info_url

            # Headers
            headers = self.rest_session.headers

            # Call REST - GET
            response = self.rest_call.get_query(
                           url = url,
                           verify = False,
                           headers = headers
            )

            # Convert response to expected data
            nodes_info = response.json()
        except Exception as e:
            self.logger.error(e)

        return nodes_info

    def multi_search_query(self, data):
        # Query result
        query_result = None

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.multi_search_url

            # Headers
            headers = self.rest_session.headers

            # Call REST - POST
            response = self.rest_call.post_query(
                           url = url,
                           verify = False,
                           headers = headers,
                           data = data
            )

            # Convert response to expected data
            query_result = response.json()
        except Exception as e:
            self.logger.error(e)

        return query_result

    def get_ms_timstamp(self):
        return int(round(time.time()) * 1000)

if __name__ == "__main__":
    pass
