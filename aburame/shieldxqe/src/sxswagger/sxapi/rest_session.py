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
import argparse

# 3rd party library
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning

# shieldx library
from sxswagger.common.custom_logger import CustomLogger

class RestSession(object):
    """ REST Session """

    def __init__(self, protocol=None, ip=None, username=None, password=None):
        # Default Parameters
        if protocol is None:
            protocol = "https"
        else:
            pass

        # Account
        self.username = username
        self.password = password

        # Singleton Logger
        self.logger = CustomLogger().get_logger()

        # Login URL + API Version
        self.login_url = "{protocol}://{ip}/".format(protocol=protocol, ip=ip)
        self.api_version = "shieldxapi/v1/"

        # This is a base URL
        self.base_url = self.login_url + self.api_version

    def login(self):
        # Basic Auth
        self.auth = HTTPBasicAuth(self.username, self.password)
        self.logger.info(self.auth)

        # Disable warnings
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
        requests.packages.urllib3.disable_warnings(SNIMissingWarning)

        # Timeout
        self.timeout = 60
        # Header
        self.headers = {
            "content-type": "application/json;charset=utf-8",
        }

        url = "{base_url}login".format(base_url=self.base_url)
        self.logger.info("URL: {url}".format(url=url))
        self.logger.info("Login Headers: {headers}".format(headers=self.headers))

        # Login: POST - establish connection
        response = requests.post(
                       url,
                       headers = self.headers,
                       auth = self.auth,
                       timeout = self.timeout,
                       verify = False
                   )

        if response.status_code == requests.codes.ok:
            # Updated header
            self.headers = {
                "content-type": "application/json;charset=utf-8",
                "x-auth-token": response.headers.get("x-auth-token"),
            }

            # Login is successful
            self.logger.info("Login OK - {username}/{password}".format(username=self.username, password=self.password))
            self.logger.info("Auth Token - {token}".format(token=self.headers["x-auth-token"]))
        else:
            self.logger.error("Login Fail - {username}/{password}".format(username=self.username, password=self.password))
            self.logger.error("Login Fail - Code: {code}".format(code=response.status_code))

    def logout(self):
        url = "{base_url}shieldxapi/logout".format(base_url=self.login_url)
        self.logger.info("URL: {url}".format(url=url))

        # Logout: POST - close connection
        response = requests.post(
                       url,
                       headers = self.headers,
                       timeout = self.timeout,
                       verify=False
                   )

        if response.status_code == requests.codes.ok:
            self.logger.info("Logout OK")
        else:
            self.logger.error("Logout Fail - Code: {code}".format(code=response.status_code))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="REST Session")
    parser.add_argument("-i","--ipaddress", help="UM IP Address.", required=True)
    parser.add_argument("-u","--username", default="api", help="Username", required=False)
    parser.add_argument("-p","--password", default="api!23$", help="Password", required=False)
    args = vars(parser.parse_args())

    # Parameters
    umip = args["ipaddress"]
    username = args["username"]
    password = args["password"]

    # REST Session
    restSession = RestSession(protocol=protocol, ip=umip, username=username, password=password)

    # Login
    restSession.login()

    # Logout
    #restSession.logout()
