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
#     ThreatPrevention

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class ThreatPrevention(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs - ACL
        self.access_control_policy_url = "policy/accesscontrolpolicy"

        # URLs - Threat Prevention Policy (TPP)
        self.content_attribute_url = "policy/threatpreventionpolicy/contentattr"
        self.protection_type_url = "policy/threatpreventionpolicy/protectiontype"
        self.tpp_url = "policy/threatpreventionpolicy"
        self.tpp_by_id_url = "policy/threatpreventionpolicy/{policy_id}"
        self.threats_by_policy_id_url = "policy/{policy_id}/threats"
        self.threat_responses_by_policy_id_url = "policy/{policy_id}/threatresponses"
        self.apps_by_policy_id_url = "policy/{policy_id}/apps"
        self.clone_tpp_responses_url = "policy/{from_policy_id}/{to_policy_id}/clonethreatresponses"
        self.bulk_update_response_url = "policy/threatresponses"

        # URLs - Threat Encyclopedia
        self.threat_encyclopedia_url = "policy/threatencyclopedia"
        self.threat_severity_url = "policy/severity"

        # URLs - URL Filtering Policy
        self.url_filtering_policy_url = "policy/urlfilteringpolicy"

        # URL separator
        self.sep_url = "/"

    def get_access_control_policy(self):
        # Access Control Policy List
        access_control_policy_list = None

        # Craft the URL
        url = self.rest_session.base_url + self.access_control_policy_url

        # Headers
        headers = self.rest_session.headers

        # Get Access Control Policy List - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            access_control_policy_list = list(response.json())
        else:
            # Empty list
            pass

        return access_control_policy_list

    def get_content_attributes(self):
        # Content Attribute
        content_attributes = None

        # Craft the URL
        url = self.rest_session.base_url + self.content_attribute_url

        # Headers
        headers = self.rest_session.headers

        # Get Content Attribute - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            content_attributes = list(response.json())
        else:
            # Empty list
            pass

        return content_attributes

    def get_threat_severities(self):
        # Threat Severities
        threat_severities = None

        # Craft the URL
        url = self.rest_session.base_url + self.threat_severity_url

        # Headers
        headers = self.rest_session.headers

        # Get Threat Severities - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            threat_severities = list(response.json())
        else:
            # Empty list
            pass

        return threat_severities

    def get_protection_types(self):
        # Protection Types
        protection_types = None

        # Craft the URL
        url = self.rest_session.base_url + self.protection_type_url

        # Headers
        headers = self.rest_session.headers

        # Get Protection Types - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            protection_types = list(response.json())
        else:
            # Empty list
            pass

        return protection_types

    def create_threat_prevention_policy(self, policy):
        # Action
        policy_id = 0

        # Craft the URL
        url = self.rest_session.base_url + self.tpp_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(policy)

        # Create TPP - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policy_id = int(response.text)
        else:
            pass

        return policy_id

    def clone_threat_prevention_policy_responses(self, from_policy_id,
            to_policy_id, response_action=None):
        # Action
        is_cloned = False

        # Craft the URL
        url = self.rest_session.base_url + \
              self.clone_tpp_responses_url.format(
                  from_policy_id=from_policy_id,
                  to_policy_id=to_policy_id
              )

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(response_action)

        # Clone TPP - PUT
        response = self.rest_call.put_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_cloned = True
        else:
            pass

        return is_cloned

    def bulk_update_threat_responses(self, response_action=None):
        # Action
        bulk_edit_success = False

        # Craft the URL
        url = self.rest_session.base_url + self.bulk_update_response_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(response_action)

        # Bulk Edit TPP Response Action - PUT
        response = self.rest_call.put_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            bulk_edit_success = True
        else:
            pass

        return bulk_edit_success

    def get_threat_prevention_policy_list(self):
        # Threat Prevention Policy List
        tpp_list = []

        # Craft the URL
        url = self.rest_session.base_url + self.tpp_url

        # Headers
        headers = self.rest_session.headers

        # Get Threat Prevention Policy List - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            tpp_list = list(response.json())
        else:
            # Empty list
            pass

        return tpp_list

    def get_threat_prevention_policy_by_id(self, policy_id):
        # Threat Prevention Policy
        tpp = None

        # Craft the URL
        url = self.rest_session.base_url + self.tpp_by_id_url.format(policy_id=policy_id)

        # Headers
        headers = self.rest_session.headers

        # Get Threat Prevention Policy by ID - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            tpp = dict(response.json())
        else:
            # Empty list
            pass

        return tpp

    def get_threat_prevention_policy_by_name(self, policy_name):
        # Threat Prevention Policy
        tpp = None

        # Get TPP List
        tpp_list = self.get_threat_prevention_policy_list()

        # Find the index of the TPP
        tpp_names = [tpp["name"] for tpp in tpp_list]

        if policy_name in tpp_names:
            index = tpp_names.index(policy_name)
            tpp = tpp_list[index]
        else:
            # TPP not found
            pass

        return tpp

    def delete_threat_prevention_policy_by_id(self, policy_id):
        # Action
        is_deleted = False

        # Craft the URL
        url = self.rest_session.base_url + self.tpp_by_id_url.format(policy_id=policy_id)

        # Headers
        headers = self.rest_session.headers

        # Delete Threat Prevention Policy by ID
        response = self.rest_call.delete_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_deleted = True
        else:
            # Empty list
            pass

        return is_deleted

    def get_threats_by_policy_id(self, policy_id):
        # Threats List
        threats = []

        # Craft the URL
        url = self.rest_session.base_url + self.threats_by_policy_id_url.format(policy_id=policy_id)

        # Headers
        headers = self.rest_session.headers

        # Get Threats - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            threats = list(response.json())
        else:
            # Empty list
            pass

        return threats

    def get_threat_responses_by_policy_id(self, policy_id):
        # Threat Responses List
        threat_responses = []

        # Craft the URL
        url = self.rest_session.base_url + self.threat_responses_by_policy_id_url.format(policy_id=policy_id)

        # Headers
        headers = self.rest_session.headers

        # Get Threat Responses - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            threat_responses = list(response.json())
        else:
            # Empty list
            pass

        return threat_responses

    def get_apps_by_policy_id(self, policy_id):
        # Apps List
        apps = []

        # Craft the URL
        url = self.rest_session.base_url + self.apps_by_policy_id_url.format(policy_id=policy_id)

        # Headers
        headers = self.rest_session.headers

        # Get Threats - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            apps = list(response.json())
        else:
            # Empty list
            pass

        return apps

    def get_threat_encyclopedia(self, pm_id, rule_id):
        # Threat Info
        threat_info = {}

        # Craft the URL
        url = self.rest_session.base_url + self.threat_encyclopedia_url + self.sep_url + rule_id + self.sep_url + pm_id

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            threat_info = dict(response.json())
        else:
            # Empty dictionary
            pass

        return threat_info

    def get_url_filtering_policy(self):
        # Policy List
        url_filter_policies = None

        # Craft the URL
        url = self.rest_session.base_url + self.url_filtering_policy_url

        # Headers
        headers = self.rest_session.headers

        # Get URL Filtering Policies - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            url_filter_policies = list(response.json())
        else:
            # Empty list
            pass

        return url_filter_policies

if __name__ == "__main__":
    pass
