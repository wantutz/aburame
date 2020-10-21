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
#
# Blacklist

# standard library
import os

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class Blacklist(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs specific to IP Blacklist
        self.blacklist_url = "accesscontrol/ipblacklist"
        self.disable_blacklist_url = "accesscontrol/ipblacklist/disable"
        self.import_by_file_url = "accesscontrol/importlistedip"
        self.import_by_feed_url = "accesscontrol/urlfeed/blacklistedips"
        self.export_listed_ip_url = "accesscontrol/export/blacklist"
        self.response_action_url = "accesscontrol/ipblacklist/action"
        self.global_settings_url = "accesscontrol/ipblacklist/globalsettings"

    def get_ip_blacklist(self):
        # Blacklists
        blacklists = None

        # Craft the URL
        url = self.rest_session.base_url + self.blacklist_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        blacklists = list(response.json())

        return blacklists

    def disable_ip_blacklist(self):
        # Action
        is_disabled = False

        # Craft the URL
        url = self.rest_session.base_url + self.disable_blacklist_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - DELETE
        response = self.rest_call.delete_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_disabled = True
        else:
            is_disabled = False

        return is_disabled

    def import_listed_ip(self, filename):
        # Action
        is_imported = False

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.import_by_file_url

            # File to import, opened
            files = {"file": (filename, open(filename), "text/plain")}

            # Use file name and exclude full path
            _, file_name = os.path.split(filename)

            # Customize header, remove "content-type".
            headers = dict(**self.rest_session.headers)
            headers.pop("content-type")

            # "param" is the name of the imported file
            data = {
                "param": file_name,
            }

            # Call REST - POST
            response = self.rest_call.post_query(
                           url = url,
                           files = files,
                           headers = headers,
                           verify = False,
                           data = data
                       )
        except Exception as e:
            self.logger.error(e)

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_imported = True
        else:
            is_imported = False

        return is_imported

    def import_listed_feed(self, urlfeed):
        # Action
        is_imported = False

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.import_by_feed_url

            # Fetch the resource name
            feed_name = urlfeed.split("/")[-1]

            # Payload
            data = json.dumps({
                "enable" : "false",
                "tenantId" : 1,
                "tenants" : [{"id": 1, "name": "default-tenant"}],
                "name" : feed_name,
                "type" : "2",
                "url" : urlfeed,
                "urlmd5" : ""
            })

            # Headers
            headers = self.rest_session.headers

            # Call REST - POST
            response = self.rest_call.post_query(
                           url = url,
                           headers = headers,
                           verify = False,
                           data = data
                       )
        except Exception as e:
            self.logger.error(e)

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_imported = True
        else:
            is_imported = False

        return is_imported

    def export_listed_ip(self, export_file = None):
        # Action
        is_exported = False

        # Blacklist
        ip_blacklist = None

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.export_listed_ip_url

            # Headers
            headers = self.rest_session.headers

            # Call REST - GET
            response = self.rest_call.get_query(
                           url = url,
                           verify = False,
                           headers = headers
                       )

            # Convert response to expected data
            if response.status_code == requests.codes.ok:
                # IP Blacklist Count
                self.logger.info("IP Blacklist Count: {}".format(len(response.text.split())))

                ip_blacklist = response.text
                is_exported = True
            else:
                self.logger.error(response.status_code)
                self.logger.error(response.content)
        except Exception as e:
            self.logger.error(e)

        try:
            if export_file is not None:
                with open(export_file, "w") as txt_file:
                    txt_file.write(ip_blacklist)
            else:
                pass
        except Exception as e:
            self.logger.error(e)

        return is_exported

    def get_ip_blacklist_global_settings(self):
        # Global settings
        ip_blacklist_globalsettings = {}

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.global_settings_url

            # Headers
            headers = self.rest_session.headers

            # Call REST - GET
            response = self.rest_call.get_query(
                           url = url,
                           verify = False,
                           headers = headers
                       )

            # Convert response to expected data
            if response.status_code == requests.codes.ok:
                ip_blacklist_globalsettings = dict(response.json())
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return ip_blacklist_globalsettings

    def set_ip_blacklist_action(self, action, frequency=30):
        # Action
        is_action_set = False

        # Blacklist - Response Action
        #     1 - Alert Only
        #     2 - Block and Alert
        # Blacklist - Frequency
        #     Currently not used
        data = json.dumps({
                   "action" : action,
                   "frequency" : frequency
               })

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.response_action_url

            # Headers
            headers = self.rest_session.headers

            # Call REST - PUT
            response = self.rest_call.put_query(
                           url = url,
                           headers = headers,
                           verify = False,
                           data = data
                       )

            # Convert response to expected data
            if response.status_code == requests.codes.ok:
                is_action_set = True
                self.logger.info("Blacklist Action Set.")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return is_action_set

if __name__ == "__main__":
    # Use Common Test Infra for Func and Unit tests
    pass
