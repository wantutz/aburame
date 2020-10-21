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
#     Malware
#     SecurityPolicySets
#     ThreatPrevention

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

class Malware(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs - Malware
        self.malware_url = "policy/malwarepolicy"
        self.malware_engines_config_url = "manage/malwareenginesconfig"

    def get_policies(self):
        # Malware Policies
        policies = None

        # Craft the URL
        url = self.rest_session.base_url + self.malware_url

        # Headers
        headers = self.rest_session.headers

        # List Policies - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policies = list(response.json())
        else:
            pass

        return policies

    def get_policy_by_name(self, policy_name):
        # Malware Policy
        malware_policy = None

        # Craft the URL
        url = self.rest_session.base_url + self.malware_url

        # Headers
        headers = self.rest_session.headers

        # List Policies - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policies = list(response.json())

            for policy in policies:
                if policy_name == policy["name"]:
                    malware_policy = policy
                    break
                else:
                    continue
        else:
            pass

        return malware_policy

    def get_policy_by_id(self, policy_id):
        # Malware Policy
        malware_policy = None

        # Craft the URL
        url = self.rest_session.base_url + self.malware_url

        # Headers
        headers = self.rest_session.headers

        # List Policies - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policies = list(response.json())

            for policy in policies:
                if policy_id == policy["id"]:
                    malware_policy = policy
                    break
                else:
                    continue
        else:
            pass

        return malware_policy

    def set_malware_config(self, malware_config):
        # Action
        is_updated = False

        # Craft the URL
        url = self.rest_session.base_url + self.malware_engines_config_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(malware_config)

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

    def create_policy(self, policy):
        # Policy ID
        policy_id = 0

        # Craft the URL
        url = self.rest_session.base_url + self.malware_url

        # Headers
        headers = self.rest_session.headers

        # Data
        data = json.dumps(policy)

        # Create malware policy - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policy_id = int(response.json())
        else:
            pass

        return policy_id

    def update_policy(self, policy):
        # Policy ID
        policy_id = 0

        # Craft the URL
        url = self.rest_session.base_url + self.malware_url

        # Headers
        headers = self.rest_session.headers

        # Data
        data = json.dumps(policy)

        # Update malware policy - PUT
        response = self.rest_call.put_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            policy_id = int(response.json())
        else:
            pass

        return policy_id

    def delete_policy(self, policy_id):
        # Action
        is_deleted = False

        # Craft the URL
        url = self.rest_session.base_url + self.malware_url + "/" + str(policy_id)

        # Headers
        headers = self.rest_session.headers

        # Delete malware policy - DELETE
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

class SecurityPolicySets(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs - Security Policy Set
        self.sps_url = "policy/securitypolicyset"
        self.sps_by_tenant_id_url = "policy/securitypolicyset/tenant/{tenant_id}"
        self.sps_by_id_url = "policy/securitypolicyset/{sps_id}"

    def create_security_policy_set(self, policy):
        # Security Policy Set ID
        policy_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.sps_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(policy)

        # Create SPS - POST
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

    def update_security_policy_set(self, policy):
        # Security Policy Set ID
        policy_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.sps_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(policy)

        # Update SPS - PUT
        response = self.rest_call.put_query(
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

    def get_security_policy_set(self):
        # Security Policy Set List
        sps_list = []

        # Craft the URL
        url = self.rest_session.base_url + self.sps_url

        # Headers
        headers = self.rest_session.headers

        # Get SPS List - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            sps_list = list(response.json())
        else:
            # Empty list
            pass

        return sps_list

    def get_sps_by_id(self, sps_id):
        # Security Policy Set
        sps = None

        # Craft the URL
        url = self.rest_session.base_url + self.sps_by_id_url.format(sps_id=sps_id)

        # Headers
        headers = self.rest_session.headers

        # Get SPS - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            sps = dict(response.json())
        else:
            # Empty list
            pass

        return sps

    def get_sps_by_name(self, sps_name):
        # Security Policy Set
        sps = None

        # Get list of SPS
        sps_list = self.get_security_policy_set()

        # Find the index of the SPS
        sps_names = [sps["name"] for sps in sps_list]

        if sps_name in sps_names:
            index = sps_names.index(sps_name)
            sps = sps_list[index]
        else:
            # SPS not found
            pass

        return sps

    def delete_security_policy_set_by_id(self, sps_id):
        # Action
        is_deleted = False

        # Craft the URL
        url = self.rest_session.base_url + self.sps_by_id_url.format(sps_id=sps_id)

        # Headers
        headers = self.rest_session.headers

        # Delete Security Policy Set by ID
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
