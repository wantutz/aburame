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
# System Under Test

# standard library
import json

# 3rd party library

# shieldx - audit log
from sxswagger.sxapi.audit_log import AuditLog

# shieldx - common
from sxswagger.common.custom_logger import CustomLogger

# shieldx - jobs api
from sxswagger.sxapi.jobs_apis import JobsApis as JobsMgmt

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - policy management
from sxswagger.sxapi.policy_management import AccessControl as ACL_Mgmt
from sxswagger.sxapi.policy_management import SecurityPolicySets as SPS_Mgmt

class SystemUnderTest(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # Aspects of system under test
        self.acl_mgmt = ACL_Mgmt(rest_session)
        self.audit_log_mgmt = AuditLog(rest_session)
        self.jobs_mgmt = JobsMgmt(rest_session)
        self.sps_mgmt = SPS_Mgmt(rest_session)
        self.sys_mgmt = SysMgmt(rest_session)

    def assign_sps(self, acl_container, policy_name):
        is_updated = False

        if policy_name is not None:
            # SPS - map name to ID
            sps_id = None
            # Get SPS by name
            sps = self.sps_mgmt.get_sps_by_name(policy_name)

            if sps is not None:
                sps_id = sps["id"]
            else:
                pass
        else:
            # SPS is Null
            policy_name = "null"
            sps_id = "null"

        # Resolve ACL container
        acl_policy = self.acl_mgmt.get_acl_by_name(acl_container)

        if acl_policy is not None:
            self.logger.info("Update ACL with SPS Name: {}".format(policy_name))
            self.logger.info("Update ACL with SPS ID: {}".format(sps_id))
            # Modify the ACL Rule in the Default ACL Policy
            acl_policy["spsId"] = sps_id
            acl_policy["aclRules"][0]["spsId"] = sps_id

            # Update the ACL
            self.logger.info("Update ACL: {}".format(acl_policy))
            is_updated = self.acl_mgmt.update_acl(acl_policy)
        else:
            # ACL Container not found
            pass

        return is_updated

    def get_sps(self, acl_container, acl_rule_order_num=0):
        policy_name = None

        # Resolve ACL container
        acl_policy = self.acl_mgmt.get_acl_by_name(acl_container)

        # Get ACL Rules
        acl_rules = acl_policy.get("aclRules", [])
        self.logger.info("ACL Rules: {}".format(acl_rules))

        # Get SPS of specified ACL Rule
        sps_id = acl_rules[acl_rule_order_num]["spsId"]
        sps = self.sps_mgmt.get_sps_by_id(sps_id)
        self.logger.info("SPS: {}".format(sps))

        if sps is not None:
            # Get SPS Name
            policy_name = sps.get("name", None)
        else:
            pass

        return policy_name

    def get_system_info(self):
        system_info = {}

        # Get the software and content versions
        versions = self.sys_mgmt.get_system_info()
        system_info["software_version"] = versions["version"]
        system_info["content_version"] = versions["contentVersion"]

        # Get the license info
        license_info = self.sys_mgmt.get_license()
        system_info["capacity"] = license_info["expected_capacity"]

        return system_info

    def get_audit_log_by_action(self, start_time, end_time, action):
        # Craft query
        query = json.dumps({
            "eventType": "AUDIT_LOG",
            "gte": start_time,
            "lte": end_time,
            "queryType": "TABLE",
            "size": 100
        })

        # Get Audit Log
        audit_log_entries = self.audit_log_mgmt.get_audit_log(query=query)

        # Filter logs by action
        filtered_logs = [entry for entry in audit_log_entries if action in entry["log"]["action"]]

        return filtered_logs

    def get_last_completed_job(self):
        # Check last completed job
        jobs = self.jobs_mgmt.get_jobs()
        completed_jobs = [job for job in jobs if job["state"] == "COMPLETED"]

        # Get Job ID
        job_id = completed_jobs[0]["id"]

        # Fetch and return job based on job ID
        return self.jobs_mgmt.get_job_by_id(job_id)

    def update_content_by_file(self, filename):
        # Update content
        is_content_update_initiated = self.sys_mgmt.file_based_update_content(filename)

        # Return status
        return is_content_update_initiated

if __name__ == "__main__":
    pass
