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
# System Management
#     - backups, control plane config, fireeye config, ldap server, license, etc.

# standard library

# 3rd party library
import gzip
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class SystemManagement(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URL specific to this Module
        self.license_url = "manage/license"
        self.activate_license_url = "manage/license/activate"
        self.system_info_url = "manage/systeminfo"
        self.staged_software_url = "manage/software/stagedversion"
        self.deployed_software_url = "manage/software/deployed"
        self.latest_software_url = "manage/software/latest"
        self.update_content_url = "manage/updatecontent"
        self.update_software_url = "manage/software/update"
        self.update_hotfix_url = "manage/software/update/hotfix"
        self.file_based_update_content_url = "manage/filebasedupdatecontent"
        self.users_url = "manage/users"

        # URL separator
        self.sep_url = "/"

    def get_system_info(self):
        # System Info
        system_info = {}

        # This is a special variable, license,  showing the license used for this library
        # self.logger.info("Test Infra License: {}".format(license))

        # Craft the URL
        url = self.rest_session.base_url + self.system_info_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        system_info = dict(response.json())

        return system_info

    def set_license(self, license=None):
        # Action
        is_license_set = False

        # No license to activate
        if license == None:
            # No-op, just get out
            return is_license_set
        else:
            # Proceed in activating license
            pass

        # Craft the URL
        url = self.rest_session.base_url + self.activate_license_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - POST
        response = self.rest_call.post_query(
                       url = url,
                       verify = False,
                       headers = headers,
                       data = license
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_license_set = True
        else:
            is_license_set = False

        return is_license_set

    def get_license(self, license=None):
        # License Info
        license_info = {}

        # Craft the URL
        if license == None:
            # Get whatever license is currently applied
            url = self.rest_session.base_url + self.license_url + self.sep_url + "dummy"
        else:
            # Get the specific license applied
            url = self.rest_session.base_url + self.license_url + self.sep_url + license

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify = False,
            headers = headers
        )

        # Convert response to expected data
        license_info = dict(response.json())

        self.logger.info("License: {}".format(license_info))

        return license_info

    def create_user(self, user_info):
        is_user_created = False

        # Craft the URL
        url = self.rest_session.base_url + self.users_url

        # Headers
        headers = self.rest_session.headers

        # Craft the payload
        data = json.dumps(user_info)

        # Call REST - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       verify = False,
                       data = data
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_user_created = True
        else:
            is_user_created = False

        return is_user_created

    def update_user(self, user_info):
        is_user_updated = False

        # Craft the URL
        url = self.rest_session.base_url + self.users_url

        # Headers
        headers = self.rest_session.headers

        # Craft the payload
        data = json.dumps(user_info)

        # Call REST - PUT
        response = self.rest_call.put_query(
                       url = url,
                       headers = headers,
                       verify = False,
                       data = data
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_user_updated = True
        else:
            is_user_updated = False

        return is_user_updated

    def get_user(self, user_login):
        # Info for specific user
        user_info = {}

        # Craft the URL
        url = self.rest_session.base_url + self.users_url + self.sep_url + user_login

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        user_info = dict(response.json())

        return user_info

    def get_users(self):
        # List of users
        users = {}

        # Craft the URL
        url = self.rest_session.base_url + self.users_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        users = list(response.json())

        return users

    def delete_user(self, user_login):
        # Action
        is_user_deleted = False

        # Craft the URL
        url = self.rest_session.base_url + self.users_url + self.sep_url + user_login

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
            is_user_deleted = True
        else:
            is_user_deleted = False

        return is_user_deleted

    def update_content(self):
        # Action
        is_content_update_initiated = False

        # Craft the URL
        url = self.rest_session.base_url + self.update_content_url

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
            is_content_update_initiated = True
        else:
            is_content_update_initiated = False

        return is_content_update_initiated

    def file_based_update_content(self, filename):
        # Action
        is_content_update_initiated = False

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.file_based_update_content_url

            # File to import
            files = {"file": (filename, open(filename, "rb"), "application/x-compressed")}

            # Customize header, remove "content-type".
            headers = dict(**self.rest_session.headers)
            headers.pop("content-type")

            # Call REST - POST
            response = self.rest_call.post_query(
                           url = url,
                           files = files,
                           verify = False,
                           headers = headers
                       )

            # Convert response to expected data
            if response.status_code == requests.codes.ok:
                is_content_update_initiated = True
            else:
                pass

        except Exception as e:
            self.logger.error(e)

        return is_content_update_initiated

    def update_hotfix(self, microservice, swversion, hotfix):
        # Action
        is_update_initiated = False

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.update_hotfix_url

            # Payload
            data = {
                "microservice": microservice,
                "swversion": swversion,
                "hotfixbuild": hotfix
            }

            # Headers
            headers = self.rest_session.headers

            # Call REST - POST
            response = self.rest_call.post_query(
                           url = url,
                           data = data,
                           verify = False,
                           headers = headers
                       )

            # Convert response to expected data
            if response.status_code == requests.codes.ok:
                is_update_initiated = True
            else:
                pass

        except Exception as e:
            self.logger.error(e)

        return is_update_initiated

    def get_staged_version(self):
        # Staged Version
        staged_version = []

        # Craft the URL
        url = self.rest_session.base_url + self.staged_software_url

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
            staged_version = list(response.json())
        else:
            pass

        return staged_version

    def get_latest_version(self):
        # Latest Version
        latest_version = []

        # Craft the URL
        url = self.rest_session.base_url + self.latest_software_url

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
            latest_version = list(response.json())
        else:
            pass

        return latest_version

    def apply_staged_software(self):
        # Staged Version
        is_update_initiated = False

        # Craft the URL
        url = self.rest_session.base_url + self.update_software_url

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
            is_update_initiated = True
        else:
            pass

        return is_update_initiated

if __name__ == "__main__":
    pass
