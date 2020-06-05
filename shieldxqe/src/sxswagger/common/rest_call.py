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
# Common library to use HTTP: GET, POST, PUT, DELETE

# standard library
import os
import time
import logging
import argparse
from contextlib import closing

# 3rd party library
import json
import requests

# shieldx library
from .custom_logger import CustomLogger

class RestCall(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

    def get_query(self, **query_kwargs):
        # Response
        response = None

        try:
            url = query_kwargs["url"]
            self.logger.info("URL: {}".format(url))
            self.logger.info("REST Session Headers: {}".format(self.rest_session.headers))

            with closing(
                requests.get(
                       **query_kwargs
                )
            ) as response:
                if response.status_code == requests.codes.ok:
                    # GET succeeded, return data
                    self.logger.info("GET OK: {}".format(response.status_code))
                    return response
                else:
                    # GET failed, check code
                    self.logger.error("GET failed: {}".format(response.status_code))
        except Exception as e:
            self.logger.error(e)

        return response

    def post_query(self, **query_kwargs):
        # Response
        response = None

        try:
            url = query_kwargs["url"]
            self.logger.info("URL: {}".format(url))
            self.logger.info("REST Session Headers: {}".format(self.rest_session.headers))

            with closing(
                requests.post(
                       **query_kwargs
                )
            ) as response:
                if response.status_code == requests.codes.ok:
                    # POST succeeded, return data
                    self.logger.info("POST OK: {}".format(response.status_code))
                    return response
                else:
                    # POST failed, check code
                    self.logger.error("POST failed: {}".format(response.status_code))
        except Exception as e:
            self.logger.error(e)

        return response

    def put_query(self, **query_kwargs):
        # Response
        response = None

        try:
            url = query_kwargs["url"]
            self.logger.info("URL: {}".format(url))
            self.logger.info("REST Session Headers: {}".format(self.rest_session.headers))

            with closing(
                requests.put(
                       **query_kwargs
                )
            ) as response:
                if response.status_code == requests.codes.ok:
                    # PUT succeeded, return data
                    self.logger.info("PUT OK: {}".format(response.status_code))
                    return response
                else:
                    # PUT failed, check code
                    self.logger.error("PUT failed: {}".format(response.status_code))
        except Exception as e:
            self.logger.error(e)

        return response

    def delete_query(self, **query_kwargs):
        # Response
        response = None

        try:
            url = query_kwargs["url"]
            self.logger.info("URL: {}".format(url))
            self.logger.info("REST Session Headers: {}".format(self.rest_session.headers))

            with closing(
                requests.delete(
                       **query_kwargs
                )
            ) as response:
                self.logger.info("Response Code: {}".format(response.status_code))

                if response.status_code == requests.codes.ok:
                    # DELETE succeeded, return data
                    self.logger.info("DELETE OK: {}".format(response.status_code))
                    return response
                else:
                    # DELETE failed, check code
                    self.logger.error("DELETE failed: {}".format(response.status_code))
        except Exception as e:
            self.logger.error(e)

        return response

if __name__ == "__main__":
    pass
