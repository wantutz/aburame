# standard library
import os
import sys
import argparse

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.sxapi.rest_session import RestSession as SxSession

from sxswagger.sxapi.threat_prevention_policy import ThreatPrevention as TPP
from sxswagger.sxapi.security_policy_set import SecurityPolicySets as SPS
from sxswagger.sxapi.access_control_policy import AccessControl as ACL
from sxswagger.sxapi.cloud_management import CloudManagement as CloudMgmt

class VirtualPatch(object):
    def __init__(self, rest_session, logger):
        # Logger
        self.logger = logger

        # Session
        self.rest_session = rest_session

        # Policy Mgmt
        self.tpp_mgmt = TPP(rest_session)
        self.sps_mgmt = SPS(rest_session)
        self.acl_mgmt = ACL(rest_session)
        self.cloud_mgmt = CloudMgmt(rest_session)

        # SX Info
        self._source_policy = "All Threats"
        self._default_acl_policy = "Default ACL Policy"

        # Payloads
        self._payload = PolicyPayload()

        # Cache All Threats
        self.all_threats_cache = {}
        self._cache_all_threats()

    def _cache_all_threats(self):
        tpp = self.tpp_mgmt.get_threat_prevention_policy_by_name(self._source_policy)
        all_threats = self.tpp_mgmt.get_threats_by_policy_id(tpp["id"])

        for threat in all_threats:
            key = "{}:{}".format(threat["protocolID"], threat["threatID"])
            self.all_threats_cache[key] = threat

    def _create_resource_group(self, rg_name, rg_components):
        resource_group = self._payload.get_rg_payload()
        resource_group["name"] = rg_name
        resource_group["description"] = rg_components["description"]
        resource_group["purpose"] = rg_components["purpose"]
        resource_group["resourceType"] = rg_components["resource_type"]
        resource_group["memberList"] = rg_components["member_list"]

        rg_id = self.cloud_mgmt.create_resource_group(resource_group)

        return rg_id

    def _delete_resource_group(self, rg_name):
        is_deleted = self.cloud_mgmt.remove_resource_group_by_name(rg_name)

        return is_deleted

    def _create_tpp(self, policy_name, tpp_components):
        self.logger.info("Creating TPP.")
        tpp_id = 0
        specific_threats = list()

        # Get specific threats
        for threat in tpp_components["threats"]:
            key = "{}:{}".format(threat["protocolID"], threat["threatID"])

            if key in self.all_threats_cache:
                specific_threats.append(self.all_threats_cache[key])
            else:
                # Rule not found, raise warning
                pass

        self.logger.info("Specific Threats: {}".format(specific_threats))

        # TPP Payload
        tpp_payload = self._payload.get_tpp_payload()
        self.logger.info("TPP Payload - Template: {}".format(tpp_payload))
        tpp_payload["name"] = policy_name
        tpp_payload["rules"] = [{"specificThreats": specific_threats}]
        self.logger.info("TPP Payload - Populated: {}".format(tpp_payload))

        tpp_id = self.tpp_mgmt.create_threat_prevention_policy(tpp_payload)
        self.logger.info("TPP Created, ID: {}".format(tpp_id))

        return tpp_id

    def _edit_response_actions(self, tpp_id, response_actions):
        threat_responses = self.tpp_mgmt.get_threat_responses_by_policy_id(tpp_id)

        for threat_response in threat_responses:
            threat_response["block"] = response_actions["block"]
            threat_response["policyId"] = tpp_id

        # Bulk Edit - Response Action Payload
        response_payload = self._payload.get_tpp_response_payload()
        response_payload["id"] = tpp_id
        response_payload["responses"] = threat_responses

        is_bulk_edit_ok = self.tpp_mgmt.bulk_update_threat_responses(response_payload)

        return is_bulk_edit_ok

    def _delete_tpp(self, policy_name):
        is_deleted = False

        # Get TPP
        tpp = self.tpp_mgmt.get_threat_prevention_policy_by_name(policy_name)

        if tpp is not None:
            # Delete
            is_deleted =  self.tpp_mgmt.delete_threat_prevention_policy_by_id(tpp["id"])
        else:
            # TPP not found, NOOP
            pass

        return is_deleted

    def _create_sps(self, policy_name, sps_components):
        # Threat Prevention Policy
        tpp = self.tpp_mgmt.get_threat_prevention_policy_by_name(sps_components["threat_prevention"])
        tpp_id = tpp["id"]
        tpp_name = tpp["name"]

        # Malware Policy
        malware_policy_id = None
        malware_policy_name = None

        # URL Filtering Policy
        url_filtering_policy_id = None
        url_filtering_policy_name = None

        # SPS Payload
        sps_payload = self._payload.get_sps_payload()
        sps_payload["name"] = policy_name
        sps_payload["threatPreventionPolicyName"] = tpp_name
        sps_payload["threatPreventionPolicyId"] = tpp_id

        sps_id = self.sps_mgmt.create_security_policy_set(sps_payload)
        self.logger.info("SPS Created, ID: {}".format(sps_id))

        return sps_id

    def _delete_sps(self, policy_name):
        is_deleted = False

        # Get SPS
        sps = self.sps_mgmt.get_sps_by_name(policy_name)

        if sps is not None:
            # Delete
            is_deleted =  self.sps_mgmt.delete_security_policy_set_by_id(sps["id"])
        else:
            # SPS not found, NOOP
            pass

        return is_deleted

    def _create_acl_rule(self, acl_rule_name, acl_rule_components):
        # Get Default Access Control Policy
        default_access_control_policy = self.acl_mgmt.get_acl_policies()[0]

        self.logger.info("Before Add - Default ACP: {}".format(default_access_control_policy))

        # Clone ACL Rule and modify relevant fields
        new_acl_rule = default_access_control_policy["aclRules"][0].copy()
        del(new_acl_rule["id"])
        new_acl_rule["name"] = acl_rule_name
        new_acl_rule["description"] = acl_rule_components["description"]
        new_acl_rule["spsId"] = acl_rule_components["sps_id"]
        new_acl_rule["destinationResourceGroupList"] = [acl_rule_components["dst_rg"]]

        # TODO
        # new_acl_rule["sourceResourceGroupList"] = (compute from RG or NS created based on WL IP from vuln scanner)
        # new_acl_rule["destinationResourceGroupList"] = (compute from RG or NS created based on WL IP from vuln scanner)

        # Append the new rule
        default_access_control_policy["aclRules"].append(new_acl_rule)

        # Fix order number, newly created rule is #1
        acl_rules_count = len(default_access_control_policy["aclRules"])

        for acl_rule in default_access_control_policy["aclRules"]:
            acl_rule["orderNum"] = acl_rules_count
            acl_rules_count -= 1

        self.logger.info("After Add - Default ACP: {}".format(default_access_control_policy))

        is_updated = self.acl_mgmt.update_acl(default_access_control_policy)

        self.logger.info("ACL Update status: {}".format(is_updated))

        return is_updated

    def _delete_acl_rule(self, acl_rule_name):
        # Get Default Access Control Policy
        default_access_control_policy = self.acl_mgmt.get_acl_policies()[0]

        self.logger.info("Before Del - Default ACP: {}".format(default_access_control_policy))

        # Delete ACL Rule
        index = 0
        for acl_rule in default_access_control_policy["aclRules"]:
            if acl_rule["name"] == acl_rule_name:
                # Pop based on index
                _ = default_access_control_policy["aclRules"].pop(index)
                break

            index += 1

        self.logger.info("After Del - Default ACP: {}".format(default_access_control_policy))

        is_updated = self.acl_mgmt.update_acl(default_access_control_policy)

        self.logger.info("ACL Update status: {}".format(is_updated))

        return is_updated

    def patch(self, artifact):
        # Application Discovery

        # 1. Analyze Vulnerability Scanner Output
        # 1a. CVE IDs to ShieldX Rule IDs
        #     List of Rules [{"pm_id": 6, "rule_id": 10114}, ...]
        threat_rules = [{"protocolID": 6, "threatID": 10114}]

        # 1b. List of IP Address (workloads)
        scanner_report_ip_set = [
            {"id": 0, "cidr": "192.168.131.5/32"},
            {"id": 0, "cidr": "192.168.131.51/32"}
        ]

        # 2. Create/resuse a resource group for workloads, Insertion = MSN
        rg_name = artifact["rg_name"]
        rg_components = {
            "description": "Virtual Patch - RG",
            "purpose": "POLICY",
            "resource_type": "CIDR",
            "member_list": scanner_report_ip_set
        }
        rg_id = self._create_resource_group(rg_name, rg_components)

        # 3. Locate/Create ACL Rule responsible for allowing relevant traffic

        # 4. Change the threat policy of the ACL

        # 4a. Create TPP
        tpp_name = artifact["tpp_name"]
        tpp_components = {
            "threats": threat_rules
        }
        tpp_id = self._create_tpp(tpp_name, tpp_components)

        # 4b. Edit Response action of each threat to block
        response_actions = {
            "block": True
        }
        is_buld_edit_ok = self._edit_response_actions(tpp_id, response_actions)

        # 4c. Compute Malware Policy, URL Filtering Policy
        mp_name = None      # "WithSXCloud"
        ufp_name = None     # "Default URL Filtering Policy"

        # 4d. Create SPS. Note: URL Filtering and Malware Policies are not defined
        sps_name = artifact["sps_name"]
        sps_components = {
            "threat_prevention": tpp_name,
            "malware": mp_name,
            "url_filtering": ufp_name,
        }
        sps_id = self._create_sps(sps_name, sps_components)

        # 4e. Create ACL Rule
        acl_rule_name = artifact["acl_rule_name"]
        acl_rule_components = {
            "description": "Virtual Patch - ACL Rule",
            "dst_rg": rg_id,
            "sps_id": sps_id
        }
        is_updated = self._create_acl_rule(acl_rule_name, acl_rule_components)

    def check(self, artifact):
        # Check TPP, SPS and ACL Rule
        self.logger.info("Check TPP, SPS and ACL Rule.")

    def cleanup(self, artifact):
        # Delete ACL Rule
        self._delete_acl_rule(artifact["acl_rule_name"])

        # Delete Resource Group
        self._delete_resource_group(artifact["rg_name"])

        # Delete SPS
        self._delete_sps(artifact["sps_name"])

        # Delete TPP
        self._delete_tpp(artifact["tpp_name"])

class PolicyPayload(object):
    def __init__(self):
        pass

    def get_tpp_payload(self):
        return {
            "id": 0,
            "isEditable": "true",
            "tenantId": 1,
            "name": "dummy",
            "rules": [
                "dummy"
            ]
        }

    def get_tpp_response_payload(self):
        return {
            "id": 0,
            "responses": [
                "dummy"
            ]
        }

    def get_sps_payload(self):
        return {
            "tenantId": 1,
            "id": 0,
            "name": "dummy",
            "accessControlPolicyId": 0,
            "isEditable": "false",
            "isDlpPolicy": "false",
            "isAnomalyDetection": "false",
            "malwarePolicyName": "null",
            "malwarePolicyId": "null",
            "threatPreventionPolicyName": "null",
            "threatPreventionPolicyId": "null",
            "urlfilteringPolicyName": "null",
            "urlfilteringPolicyId": "null"
        }

    def get_rg_payload(self):
        return {
            "id": 0,
            "name": "dummy",
            "description": "dummy",
            "purpose": "dummy",
            "infraIDs": [],
            "dynamic": "false",
            "regex": "none",
            "resourceType": "dummy",
            "memberList": "dummy"
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Virtual Patch tool.")
    parser.add_argument("-i","--ipaddress", help="ShieldX - Mgmt. IP Address.", required=True)
    parser.add_argument("-a","--action", default="check", help="Action: patch | check | cleanup", required=False)
    args = vars(parser.parse_args())

    # Take parameters
    ip = args["ipaddress"]
    username = os.environ.get("SHIELDX_USER")
    password = os.environ.get("SHIELDX_PASS")
    action = args["action"]

    # Initialize logger
    logger = CustomLogger().get_logger()

    if username is None or password is None:
        logger.warning("Please set username and password as environment variables.")
        sys.exit()

    # Establish REST connection
    sx_session = SxSession(ip=ip, username=username, password=password)
    sx_session.login()

    try:
        # Initialize
        virtual_patch = VirtualPatch(sx_session, logger)

        # Artifacts
        artifact = {
            "rg_name": "virtual_patch_rg",
            "tpp_name": "virtual_patch_tpp",
            "sps_name": "virtual_patch_sps",
            "acl_rule_name": "virtual_patch_acl_rule",
        }

        # Proceed based on action
        if action.lower() == "patch":
            virtual_patch.patch(artifact)
        elif action.lower() == "check":
            virtual_patch.check(artifact)
        elif action.lower() == "cleanup":
            virtual_patch.cleanup(artifact)
        else:
            logger.warning("Unknown action, {}".format(action))
    except KeyboardInterrupt as e:
        logger.info("Task done. Goodbye.")
    except Exception as e:
        logger.error(e)
        
    # Logout
    sx_session.logout()

# Sample Run
# python virtual_patch.py -i 172.16.27.73
