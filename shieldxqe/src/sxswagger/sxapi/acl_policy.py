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

# Author: tony
#
# accesscontrol

# standard library
import os
import time
import sys
import logging
import argparse
from contextlib import closing

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall
from sxswagger.sxapi.group_insert import GroupandInsert


class AccessControl(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # fetched data
        self.data = None

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs specific to ACL's
        self.accesscontrol_policy_url = "policy/accesscontrolpolicy"
        self.accesscontrol_policy_ruleadd = "policy/accesscontrolpolicy"
        self.accesscontrol_policy_nondefaultacl = "policy/accesscontrolpolicy"
        self.accesscontrol_policy_nondefaultacl_del = "policy/accesscontrolpolicy/"
        self.accesscontrol_policy_byruleid = "policy/accesscontrolpolicy/rules/"
        self.accesscontrol_policy_bychassisid = "policy/accesscontrolpolicy/chassis/"
        self.accesscontrol_policy_byinfraid = "policy/accesscontrolpolicy/infra/"
        self.accesscontrol_policy_byaclid = "policy/accesscontrolpolicy/"
        self.accesscontrol_policy_bytenantid = "policy/accesscontrolpolicy/tenant/"
        self.accesscontrol_policy_ruleadd_policyid = "policy/accesscontrolpolicy/rule"

    def get_access_controllist(self):
        accesscontrol = None

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        accesscontrol = list(response.json())
        return accesscontrol

    def add_access_control_rule(self):
        rule_added = False

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        accesscontrollist = list(response.json())
        for aid in accesscontrollist:
            if aid["name"] == 'Default ACL Policy':
                aclpolicyid = int(aid['id'])
                break

        data = json.dumps({
            "id": aclpolicyid,
            "name": "Default ACL Policy",
            "tenantId": None,
            "aclRules": [
                {
                    "action": "PERMIT",
                    "description": "",
                    "destinationApps": "",
                    "destinationCidrs": "",
                    "destinationPortRanges": "",
                    "name": "rule-51",
                    "destinationResourceGroupList": [

                    ],
                    "enableTLSInspection": False,
                    "enabled": True,
                    "orderNum": 1,
                    "resourcegroupNames": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "destinationProtocol": None,
                    "spsId": 5,
                    "tcpSessionTimeout": 1800,
                    "hitStats": None,
                    "tlsInspection": "DISABLED",
                    "serviceList": [

                    ]
                },
                {
                    "id": 4,
                    "name": "Default",
                    "description": None,
                    "orderNum": 2,
                    "enabled": True,
                    "destinationResourceGroupList": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "serviceList": [

                    ],
                    "destinationApps": "",
                    "syslog": False,
                    "tcpSessionTimeout": 1800,
                    "tlsInspection": "DISABLED",
                    "packetCapture": "DISABLED",
                    "spsId": 5,
                    "action": "PERMIT",
                    "destinationProtocol": None,
                    "destinationPortRanges": None,
                    "userType": "HUMAN",
                    "user": "admin",
                    "mapOfChangeLogPerTS": None,
                    "gmId": None
                }
            ],
            "infraMap": {
                "2": "tonyinf"
            },
            "rgNameMap": None,
            "spsNameMap": None,
            "serviceNameMap": None
        })
        try:
            # Craft the URL
            url = self.rest_session.base_url + self.accesscontrol_policy_ruleadd

            # Headers
            headers = self.rest_session.headers

            # Call REST - PUT
            response = self.rest_call.put_query(
            url=url,
            headers=headers,
            verify=False,
            data=data
        )
            if response.status_code == requests.codes.ok:
                rule_added = True
                self.logger.info("New rule added to Default ACL.")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return rule_added

    def add_srcdst_access_control_rule(self, dstrg_id, srcrg_id, rule_nm):
        rules_added = False
        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        accesscontrollist = list(response.json())
        for aid in accesscontrollist:
            if aid["name"] == 'Default ACL Policy':
                aclpolicyid = int(aid['id'])
                break

        group_handle = GroupandInsert(self.rest_session)
        rgid1 = str(dstrg_id)
        rgid2 = str(srcrg_id)

        newacl_add = [{
            "id": aclpolicyid,
            "name": "Default ACL Policy",
            "tenantId": None,
            "aclRules": [
                {
                    "action": "PERMIT",
                    "description": "",
                    "destinationApps": "",
                    "destinationCidrs": "",
                    "destinationPortRanges": "",
                    "name": "RG-1 to RG-2",
                    "destinationResourceGroupList": [
                        15
                    ],
                    "enableTLSInspection": False,
                    "enabled": True,
                    "orderNum": 1,
                    "resourcegroupNames": [

                    ],
                    "sourceResourceGroupList": [
                        14
                    ],
                    "destinationProtocol": None,
                    "spsId": 5,
                    "tcpSessionTimeout": 1800,
                    "hitStats": None,
                    "tlsInspection": "DISABLED",
                    "serviceList": [
                        215
                    ]
                },
                {
                    "id": 4,
                    "name": "Default",
                    "description": None,
                    "orderNum": 2,
                    "enabled": True,
                    "destinationResourceGroupList": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "serviceList": [

                    ],
                    "destinationApps": "",
                    "syslog": False,
                    "tcpSessionTimeout": 1800,
                    "tlsInspection": "DISABLED",
                    "packetCapture": "DISABLED",
                    "spsId": 5,
                    "action": "PERMIT",
                    "destinationProtocol": None,
                    "destinationPortRanges": None,
                    "userType": "HUMAN",
                    "user": "admin",
                    "mapOfChangeLogPerTS": None,
                    "gmId": None
                }
            ],
            "infraMap": {
                "2": "tonyinf-test2"
            },
            "rgNameMap": None,
            "spsNameMap": None,
            "serviceNameMap": None
        }]

        for srcdstid in newacl_add:
            if srcdstid["name"] == "Default ACL Policy":
                srcdstid["aclRules"][0]["name"] = rule_nm
                srcdstid["aclRules"][0]["destinationResourceGroupList"] = [rgid1]
                srcdstid["aclRules"][0]["sourceResourceGroupList"] = [rgid2]

        data = json.dumps(newacl_add)
        data = str(data)[1:-1]

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.accesscontrol_policy_ruleadd

            # Headers
            headers = self.rest_session.headers

            # Call REST - PUT
            response = self.rest_call.put_query(
            url=url,
            headers=headers,
            verify=False,
            data=data
        )
            if response.status_code == requests.codes.ok:
                rules_added = True
                self.logger.info("New rules added with src and dst.")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return rules_added

    def add_nondefault_acl_policy(self):

            # Craft the URL
            url = self.rest_session.base_url + self.accesscontrol_policy_nondefaultacl

            # Headers
            headers = self.rest_session.headers

            # Payload-1
            data1 = json.dumps({
                "id": 0,
                "name": "nondefault_acl_policy",
                "tenantId": 1,
                "aclRules": [
                    {
                        "action": "PERMIT",
                        "description": "Default rule",
                        "destinationApps": "",
                        "destinationCidrs": "",
                        "destinationPortRanges": "",
                        "name": "Default",
                        "destinationResourceGroupList": [

                        ],
                        "enableTLSInspection": False,
                        "enabled": True,
                        "id": 0,
                        "orderNum": 1,
                        "resourcegroupNames": [

                        ],
                        "sourceResourceGroupList": [

                        ],
                        "destinationProtocol": None,
                        "spsId": 5,
                        "tcpSessionTimeout": 1800,
                        "hitStats": None,
                        "tlsInspection": "DISABLED"
                    }
                ]
            })

            # Call REST - POST
            response = self.rest_call.post_query(
                           url = url,
                           headers = headers,
                           verify=False,
                           data = data1
                       )
            nondefault_acl_id = int(response.json())

            # Payload-2
            payload = [{
                "id": 0,
                "name": "nondefault_acl_policy",
                "tenantId": 1,
                "aclRules": [
                    {
                        "id": 0,
                        "name": "Default",
                        "description": "Default rule",
                        "orderNum": 1,
                        "enabled": True,
                        "destinationResourceGroupList": [

                        ],
                        "sourceResourceGroupList": [

                        ],
                        "serviceList": [

                        ],
                        "destinationApps": "",
                        "syslog": False,
                        "tcpSessionTimeout": 1800,
                        "tlsInspection": "DISABLED",
                        "packetCapture": None,
                        "spsId": 5,
                        "action": "PERMIT",
                        "destinationProtocol": None,
                        "destinationPortRanges": "",
                        "userType": "HUMAN",
                        "user": None,
                        "mapOfChangeLogPerTS": None,
                        "gmId": None
                    }
                ],
                "infraMap": {

                },
                "rgNameMap": None,
                "spsNameMap": None,
                "serviceNameMap": None
            }]
            for aid in payload:
                if aid["id"] == 0:
                    aid["id"] = nondefault_acl_id
                    aid["aclRules"][0]["id"] = nondefault_acl_id+1
            data2 = json.dumps(payload)
            data2 = str(data2)[1:-1]

            # Call REST - PUT
            response = self.rest_call.put_query(
            url=url,
            headers=headers,
            verify=False,
            data=data2
        )
            if response.status_code == requests.codes.ok:
                print("Non Default ACL policy created successfully")
            else:
                print("Non default ACL creation not successful")

                return nondefault_acl_id

    def add_tls_rule(self):
        tls_rule_added = False

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        accesscontrollist = list(response.json())
        for aid in accesscontrollist:
            if aid["name"] == 'Default ACL Policy':
                aclpolicyid = int(aid['id'])
                break

        data = json.dumps({
            "id": aclpolicyid,
            "name": "Default ACL Policy",
            "tenantId": None,
            "aclRules": [
                {
                    "action": "PERMIT",
                    "description": "",
                    "destinationApps": "",
                    "destinationCidrs": "",
                    "destinationPortRanges": "",
                    "name": "Enable_TLS",
                    "destinationResourceGroupList": [

                    ],
                    "enableTLSInspection": True,
                    "enabled": True,
                    "orderNum": 1,
                    "resourcegroupNames": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "destinationProtocol": None,
                    "spsId": 5,
                    "tcpSessionTimeout": 1800,
                    "hitStats": None,
                    "tlsInspection": "INBOUND",
                    "serviceList": [
                        92
                    ],
                    "syslog": False,
                    "packetCapture": "DISABLED"
                },
                {
                    "id": 4,
                    "name": "Default",
                    "description": None,
                    "orderNum": 2,
                    "enabled": True,
                    "destinationResourceGroupList": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "serviceList": [

                    ],
                    "destinationApps": "",
                    "syslog": False,
                    "tcpSessionTimeout": 1800,
                    "tlsInspection": "DISABLED",
                    "packetCapture": "DISABLED",
                    "spsId": 5,
                    "action": "PERMIT",
                    "destinationProtocol": None,
                    "destinationPortRanges": None,
                    "userType": "HUMAN",
                    "user": "admin",
                    "mapOfChangeLogPerTS": None,
                    "gmId": None
                }
            ],
            "infraMap": {
                "2": "tonyinf"
            },
            "rgNameMap": None,
            "spsNameMap": None,
            "serviceNameMap": None
        })

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.accesscontrol_policy_ruleadd

            # Headers
            headers = self.rest_session.headers

            # Call REST - PUT
            response = self.rest_call.put_query(
            url=url,
            headers=headers,
            verify=False,
            data=data
        )
            if response.status_code == requests.codes.ok:
                tls_rule_added = True
                self.logger.info("TLS policy enabled successfully.")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return tls_rule_added

    def add_multirule_httpping_service(self):
        multi_rule_added = False

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        accesscontrollist = list(response.json())
        for aid in accesscontrollist:
            if aid["name"] == 'Default ACL Policy':
                aclpolicyid = int(aid['id'])
                break

        data = json.dumps({
            "id": aclpolicyid,
            "name": "Default ACL Policy",
            "tenantId": None,
            "aclRules": [
                {
                    "action": "DENY",
                    "description": "",
                    "destinationApps": "",
                    "destinationCidrs": "",
                    "destinationPortRanges": "",
                    "name": "rule-2",
                    "destinationResourceGroupList": [

                    ],
                    "enableTLSInspection": False,
                    "enabled": True,
                    "orderNum": 1,
                    "resourcegroupNames": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "destinationProtocol": None,
                    "spsId": 5,
                    "tcpSessionTimeout": 1800,
                    "hitStats": None,
                    "tlsInspection": "DISABLED",
                    "serviceList": [
                        215
                    ]
                },
                {
                    "id": 165,
                    "name": "rule-1",
                    "description": "",
                    "orderNum": 2,
                    "enabled": True,
                    "destinationResourceGroupList": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "serviceList": [
                        25
                    ],
                    "destinationApps": "",
                    "syslog": False,
                    "tcpSessionTimeout": 1800,
                    "tlsInspection": "DISABLED",
                    "packetCapture": None,
                    "spsId": 5,
                    "action": "PERMIT",
                    "hitStats": {
                        "ruleId": 165,
                        "hitCount": 0
                    },
                    "destinationProtocol": None,
                    "destinationPortRanges": "",
                    "userType": "HUMAN",
                    "user": None,
                    "mapOfChangeLogPerTS": None,
                    "gmId": None,
                    "enableTLSInspection": True
                },
                {
                    "id": 4,
                    "name": "Default",
                    "description": None,
                    "orderNum": 3,
                    "enabled": True,
                    "destinationResourceGroupList": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "serviceList": [

                    ],
                    "destinationApps": "",
                    "syslog": False,
                    "tcpSessionTimeout": 1800,
                    "tlsInspection": "DISABLED",
                    "packetCapture": "DISABLED",
                    "spsId": 5,
                    "action": "PERMIT",
                    "destinationProtocol": None,
                    "destinationPortRanges": None,
                    "userType": "HUMAN",
                    "user": "admin",
                    "mapOfChangeLogPerTS": None,
                    "gmId": None
                }
            ],
            "infraMap": {
                "2": "tonyinf"
            },
            "rgNameMap": None,
            "spsNameMap": None,
            "serviceNameMap": None
        })

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.accesscontrol_policy_ruleadd

            # Headers
            headers = self.rest_session.headers

            # Call REST - PUT
            response = self.rest_call.put_query(
            url=url,
            headers=headers,
            verify=False,
            data=data
        )
            if response.status_code == requests.codes.ok:
                multi_rule_added = True
                self.logger.info("ACL rules with HTTP and Ping services added")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)
        return multi_rule_added

    def del_all_defaultacl_rules(self):
        all_rule_del = False

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        accesscontrollist = list(response.json())
        for aid in accesscontrollist:
            if aid["name"] == 'Default ACL Policy':
                aclpolicyid = int(aid['id'])
                break

        data = json.dumps({
            "id": aclpolicyid,
            "name": "Default ACL Policy",
            "tenantId": None,
            "aclRules": [
                {
                    "id": 4,
                    "name": "Default",
                    "description": None,
                    "orderNum": 1,
                    "enabled": True,
                    "destinationResourceGroupList": [

                    ],
                    "sourceResourceGroupList": [

                    ],
                    "serviceList": [

                    ],
                    "destinationApps": "",
                    "syslog": False,
                    "tcpSessionTimeout": 1800,
                    "tlsInspection": "DISABLED",
                    "packetCapture": "DISABLED",
                    "spsId": 5,
                    "action": "PERMIT",
                    "destinationProtocol": None,
                    "destinationPortRanges": None,
                    "userType": "HUMAN",
                    "user": "admin2",
                    "mapOfChangeLogPerTS": None,
                    "gmId": None
                }
            ],
            "infraMap": {
                "2": "tonyinf"
            },
            "rgNameMap": None,
            "spsNameMap": None,
            "serviceNameMap": None
        })

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.accesscontrol_policy_ruleadd

            # Headers
            headers = self.rest_session.headers

            # Call REST - PUT
            response = self.rest_call.put_query(
            url=url,
            headers=headers,
            verify=False,
            data=data
        )
            if response.status_code == requests.codes.ok:
                all_rule_del = True
                self.logger.info("All rules deleted from the default ACL policy")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)
        return all_rule_del

    def del_nondefaultacl_policy(self):
        del_nondefault_acl = False

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        accesscontrollist = list(response.json())
        for aid in accesscontrollist:
            if aid["name"] == 'nondefault_acl_policy':
                aclpolicyid = str(aid['id'])
                break

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_nondefaultacl_del + aclpolicyid

        # Headers
        headers = self.rest_session.headers

        # Call REST - DELETE
        response = self.rest_call.delete_query(
                       url = url,
                       verify=False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            del_nondefault_acl = True
        else:
            del_nondefault_acl = False

        return del_nondefault_acl

    def del_aclpolicy_aclid(self,acl_policy_id):
        del_aclpolicy_aclid = False

        aclid_policy = str(acl_policy_id)

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_byaclid + aclid_policy

        # Headers
        headers = self.rest_session.headers

        # Call REST - DELETE
        response = self.rest_call.delete_query(
                       url = url,
                       verify=False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            del_aclpolicy_aclid = True
        else:
            del_aclpolicy_aclid = False

        return del_aclpolicy_aclid

    def get_aclrule_ruleid(self,aclruleid):
        obtain_aclrule_byid = False

        aclruleid = str(aclruleid)

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_byruleid + aclruleid

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        if response.status_code == requests.codes.ok:
            accesscontrollist = response.content
            obtain_aclrule_byid = True
        else:
            obtain_aclrule_byid = False

        return accesscontrollist

    def get_aclpolicy_chassisid(self,aclpolicychassisid):
        obtain_aclpolicy_bychassisid = False

        aclpolicychassisid = str(aclpolicychassisid)

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_bychassisid + aclpolicychassisid

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        if response.status_code == requests.codes.ok:
            accesscontrol_list = response.content
            obtain_aclpolicy_bychassisid = True
        else:
            obtain_aclpolicy_bychassisid = False

        return accesscontrol_list

    def get_aclpolicy_infraid(self,aclpolicyinfraid):
        obtain_aclpolicy_byinfraid = False

        aclpolicyinfraid = str(aclpolicyinfraid)

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_byinfraid + aclpolicyinfraid

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        if response.status_code == requests.codes.ok:
            ac_list = response.content
            obtain_aclpolicy_byinfraid = True
        else:
            obtain_aclpolicy_byinfraid = False

        return ac_list

    def get_aclpolicy_aclid(self,aclpolicyid):
        obtain_aclpolicy_byaclid = False

        aclpolicyid = str(aclpolicyid)

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_byaclid + aclpolicyid

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        if response.status_code == requests.codes.ok:
            accesscontrolpolicy = response.content
            obtain_aclpolicy_byaclid = True
        else:
            obtain_aclpolicy_byaclid = False

        return accesscontrolpolicy

    def get_aclpolicy_tenantid(self,aclpolicytenantid):
        obtain_aclpolicy_bytenantid = False

        aclpolicytenantid = str(aclpolicytenantid)

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_bytenantid + aclpolicytenantid

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        if response.status_code == requests.codes.ok:
            accesscontrol_policy = response.content
            obtain_aclpolicy_bytenantid = True
        else:
            obtain_aclpolicy_bytenantid = False

        return accesscontrol_policy

    def add_aclrule_aclpolicyid(self,aclrule,aclpolicy_id):
        aclrule_addbypolicyid = False

        data = json.dumps(aclrule)
        aclpolid = "?aclPolicyId={0}".format(aclpolicy_id)

        # Craft the URL
        url = self.rest_session.base_url + self.accesscontrol_policy_ruleadd_policyid + aclpolid

        # Headers
        headers = self.rest_session.headers

        # Call REST - PUT
        response = self.rest_call.put_query(
            url = url,
            verify=False,
            headers = headers,
            data = data
        )
        if response.status_code == requests.codes.ok:
            aclrule_addbypolicyid = True
        else:
            aclrule_addbypolicyid = False

        return aclrule_addbypolicyid

if __name__ == "__main__":
    pass
