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
# Demo REST library
#

# standard library
from contextlib import closing

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger

class SxDemo(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # fetched data
        self.data = None

        # REST Session
        self.rest_session = rest_session

        # URL specific to this Module
        self.license_url = "manage/license/"

    def get_capacity1(self):
        # Dummy should not be needed for this call!
        license = "dummy"

        # Expected Capacity
        capacity = None

        try:
            url = self.rest_session.base_url + self.license_url + license
            self.logger.info("URL: {}".format(url))
            self.logger.info("REST Session Headers: {}".format(self.rest_session.headers))
            self.logger.info("Payload: {}".format(license))

            with closing(
                requests.get(
                       url,
                       headers = self.rest_session.headers,
                       timeout = self.rest_session.timeout,
                       verify=False
                )

            ) as response:
                self.logger.info("Response Code: {}".format(response.status_code))

                if response.status_code == requests.codes.ok:
                    # Fetch capacity from license call.
                    for license_key, license_value in response.json().items():
                        if license_key == "expected_capacity":
                            capacity = license_value
                            break
                        else:
                            pass
                else:
                    self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return capacity

    def get_capacity2(self):
        # Dummy should not be needed for this call!
        license = "dummy"

        # Expected Capacity
        capacity = None

        try:
            url = self.rest_session.base_url + self.license_url + license
            self.logger.info("URL: {}".format(url))
            self.logger.info("REST Session Headers: {}".format(self.rest_session.headers))
            self.logger.info("Payload: {}".format(license))

            with closing(
                requests.get(
                       url,
                       headers = self.rest_session.headers,
                       timeout = self.rest_session.timeout,
                       verify = False
                )

            ) as response:
                self.logger.info("Response Code: {}".format(response.status_code))

                if response.status_code == requests.codes.ok:
                    # Fetch capacity from license call.
                    license_dict = dict(response.json())
                    if "expected_capacity" in license_dict:
                        capacity = license_dict["expected_capacity"]
                    else:
                        pass
                else:
                    self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return capacity

    def get_capacity3(self):
        # Dummy should not be needed for this call!
        license = "dummy"

        # Expected Capacity
        capacity = None

        try:
            url = self.rest_session.base_url + self.license_url + license
            self.logger.info("URL: {}".format(url))
            self.logger.info("REST Session Headers: {}".format(self.rest_session.headers))
            self.logger.info("Payload: {}".format(license))

            with closing(
                requests.get(
                       url,
                       headers = self.rest_session.headers,
                       timeout = self.rest_session.timeout,
                       verify = False
                )

            ) as response:
                self.logger.info("Response Code: {}".format(response.status_code))

                if response.status_code == requests.codes.ok:
                    license_dict = json.loads(response.text)
                    if "expected_capacity" in license_dict:
                        capacity = license_dict["expected_capacity"]
                    else:
                        pass
                else:
                    # debugging
                    self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return capacity

if __name__ == "__main__":
    pass
