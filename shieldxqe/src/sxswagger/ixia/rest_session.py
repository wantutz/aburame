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

# REST Session
# Data:
#   Protocol for connection, http or https
#   IP Address of the UM
#   User
#   Password
# Method:
#   login()
#   logout()
#

# standard library

# 3rd party library
import json
import requests

from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning

# shieldx library
from sxswagger.common.custom_logger import CustomLogger

class RestSession(object):
    """ IXIA REST Session """

    def __init__(self, protocol=None, ip=None, username=None, password=None):
        # Default Parameters, manual location redirection
        if protocol is None:
            protocol = "https"
        else:
            pass

        # Account
        self.username = username
        self.password = password

        # Singleton Logger
        self.logger = CustomLogger().get_logger()

        # Timeout
        self.timeout = 60
        # Header
        self.headers = {
            "content-type": "application/json;charset=utf-8",
        }

        # Base URL + API Version
        self.proto_ip_url = "{protocol}://{ip}/".format(protocol=protocol, ip=ip)
        self.api_version = "bps/api/v1/"

        # Login/Logout - Session URL
        self.session_url = "auth/session"

        # This is a base URL
        self.base_url = self.proto_ip_url + self.api_version

    def login(self):
        # Basic Auth
        data = json.dumps({"username": self.username, "password": self.password})

        # Disable warnings
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
        requests.packages.urllib3.disable_warnings(SNIMissingWarning)

        url = self.base_url + self.session_url
        self.logger.info("URL: {url}".format(url=url))
        self.logger.info("Login Headers: {headers}".format(headers=self.headers))

        # Timeout
        self.timeout = 60

        # Login: POST - establish connection
        response = requests.post(
                       url,
                       headers=self.headers,
                       data=data,
                       timeout=self.timeout,
                       verify=False
                   )

        if response.status_code == requests.codes.ok:
            # Session Info
            session_info = dict(response.json())
            self.api_key = session_info["apiKey"]
            self.session_name = session_info["sessionName"]
            self.session_id = session_info["sessionId"]
            self.user_account_url = session_info["userAccountUrl"]

            # Create Cookie
            self.cookie = "{}={}".format(self.session_name, self.session_id)

            # Login is successful
            self.logger.info("Login OK - {username}/{password}".format(username=self.username, password=self.password))
            self.logger.info("API Key - {}".format(self.api_key))
            self.logger.info("Cookie - {}".format(self.cookie))
            self.logger.info("User Acct URL - {}".format(self.user_account_url))
        else:
            self.logger.error("Logged Fail - {username}/{password}".format(username=self.username, password=self.password))

    def logout(self):
        url = self.base_url + self.session_url
        self.logger.info("URL: {url}".format(url=url))
        self.logger.info("Login Headers: {headers}".format(headers=self.headers))

        # Headers
        self.headers = {"Cookie": self.cookie}
        # Timeout
        self.timeout = 60

        # Logout: DELETE - close connection
        response = requests.delete(
                       url,
                       headers=self.headers,
                       timeout=self.timeout,
                       verify=False
                   )

        if response.status_code == requests.codes.no_content:
            self.logger.info("Response Text: {}".format(response.text))
            self.logger.info("Logout successful.")
        else:
            self.logger.error("Unable to logout.")

if __name__ == "__main__":
    pass
