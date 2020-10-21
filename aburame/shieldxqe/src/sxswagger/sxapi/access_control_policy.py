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
# Policy Management
#     AccessControl

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class AccessControl(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs - Access Control
        self.acl_url = "policy/accesscontrolpolicy"
        self.acl_by_id_url = "policy/accesscontrolpolicy/{acl_id}"
        self.acl_by_infra_url = "policy/accesscontrolpolicy/infra/{infra_id}"
        self.acl_by_tenant_url = "policy/accesscontrolpolicy/tenant/{tenant_id}"
        self.acl_by_dataplane_url = "policy/accesscontrolpolicy/chassis/{dp_id}"

    def get_acl_policies(self):
        # ACL Policies
        acl_list = None

        # Craft the URL
        url = self.rest_session.base_url + self.acl_url

        # Headers
        headers = self.rest_session.headers

        # Get ACL Policies - GET (List)
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            acl_list = list(response.json())
        else:
            pass

        return acl_list

    def get_acl_by_name(self, acl_name):
        # ACL Policy
        acl_policy = None
        index = -1

        # Get ACL Policies
        acl_list = self.get_acl_policies()

        # Find the index of the ACL
        acl_names = [acl["name"] for acl in acl_list]
        index = acl_names.index(acl_name)

        # Get specific ACL based on index
        if index >= 0:
            acl_policy = acl_list[index]
        else:
            pass

        return acl_policy

    def get_acl_by_id(self, acl_id):
        # ACL Policy
        acl_policy = None
        index = -1

        # Get ACL Policies
        acl_list = self.get_acl_policies()

        # Find the index of the ACL
        acl_ids = [acl["id"] for acl in acl_list]
        index = acl_names.ids(acl_id)

        # Get specific ACL based on index
        if index >= 0:
            acl_policy = acl_list[index]
        else:
            pass

        return acl_policy

    def update_acl(self, acl_policy):
        # Action
        is_updated = False

        # Craft the URL
        url = self.rest_session.base_url + self.acl_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(acl_policy)

        # Update ACL - PUT
        response = self.rest_call.put_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_updated = True
        else:
            pass

        return is_updated

    def delete_acl(self, acl_id):
        # Action
        is_deleted = False

        # Craft the URL
        url = self.rest_session.base_url + self.acl_by_id_url.format(acl_id=acl_id)

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(acl_policy)

        # Delete ACL - DELETE
        response = self.rest_call.delete_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_deleted = True
        else:
            pass

        return is_deleted

if __name__ == "__main__":
    pass
