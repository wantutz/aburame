# 3rd party library
import json
from datetime import datetime

import yaml

import requests
import time

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall
from sxswagger.sxapi.acl_policy import AccessControl


class PolicyGen(object):
    def __init__(self, rest_session):

        self.test_aws_flow_connection = 'appconfig/testawss3connection'
        self.post_aws_flow_log = 'appconfig/flowlogsstorageconfig'
        self.get_all_cloud_listing = 'infras'
        self.app_instance = 'applications/instances'
        self.sequence_apps = 'applications/sequence'
        self.logger = CustomLogger().get_logger()
        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)
        self.acl_caller = AccessControl(rest_session)

        self.new_acl_count = "applications/statistics"
        self.forward_test = "applications/forwardtest"
        self.get_forward_time = "applications/forwardtest/starttime"
        self.implement_all_CS = "applications/services/implement"
        self.purge_data = "appconfig/purgedata"
        self.implement_all = "applications/instances/implement"
        self.summary_apps = "applications/summarydetails"
        self.delete_apps = "applications/instances"
        self.filter_config = 'appconfig/filterconfig'
        self.get_networks = 'infras/networkset'
        self.deny_policy = 'applications/lasthitaclrule'
        self.last_hit_rule = 'applications/lasthitaclrule'
        self.get_violations_api = 'policy/accesscontrolpolicy/rulehits/'
        self.create_acl_rule = 'policy/accesscontrolpolicy/rule'
        self.proposed_acl = 'applications/aclrules/propose'
        self.acl_policy ='policy/accesscontrolpolicy'
        self.resource_group = 'applications/resourcegroups'

    def get_acl_connections(self):
        url = self.rest_session.base_url + self.new_acl_count
        headers = self.rest_session.headers
        response = self.rest_call.get_query(
            url=url,
            headers=headers, verify=False
        )
        resp = json.loads(response.content)
        return resp

    def start_forward_testing(self):
        url = self.rest_session.base_url + self.forward_test
        headers = self.rest_session.headers
        response = self.rest_call.put_query(url=url, headers=headers, verify=False)
        ts = datetime.now()
        time_started = datetime.timestamp(ts)
        status = response.status_code
        return status, time_started

    def get_forward_testing_time(self):
        url = self.rest_session.base_url + self.get_forward_time
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        timestamp = json.loads(response.content)
        forward_testing_time = datetime.fromtimestamp(timestamp / 1000).strftime('%c')
        return forward_testing_time, timestamp

    def implement_all_commonservices(self):
        url = self.rest_session.base_url + self.implement_all_CS
        headers = self.rest_session.headers
        response = self.rest_call.post_query(url=url, headers=headers, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            return status
        else:
            return response.content

    def purge_data_gm(self):
        url = self.rest_session.base_url + self.purge_data
        headers = self.rest_session.headers
        response = self.rest_call.put_query(url=url, headers=headers, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            return status

    def app_summary(self):
        url = self.rest_session.base_url + self.summary_apps
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            content2 = json.loads(response.content)
            apps_summary = content2["All Applications"]
            return apps_summary,content2

    def implement_all_apps(self):
        url = self.rest_session.base_url + self.implement_all
        headers = self.rest_session.headers
        data,content = self.app_summary()
        final_data = content["All Applications"]
        print(final_data)
        data = json.dumps(final_data)
        response = self.rest_call.post_query(url=url, headers=headers, data=data, timeout=400, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            return status
        else:
            return response.content

    def get_total_acl_proposed(self):
        url = self.rest_session.base_url + self.proposed_acl
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url,headers=headers,timeout=100,verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            content2 = response.content
            acl_rules =json.loads(content2)
            rule_num = len(acl_rules)
            return status,rule_num

        else:
            return status,response.content

    def get_acl_rules_policy(self):
        url = self.rest_session.base_url + self.acl_policy
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url,headers=headers,timeout=10,verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            content = response.content
            content2 = json.loads(content)
            for i in content2:
                if i["name"] == "Default ACL Policy":
                    rule2 =len(i["aclRules"])
                    return status,rule2
        else:
            return status,response.content

    def delete_all(self):
        url = self.rest_session.base_url + self.delete_apps
        headers = self.rest_session.headers
        response = self.rest_call.delete_query(url=url, headers=headers, timeout=400, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            return status
        else:
            return response.content

    def get_filter_config(self):
        url = self.rest_session.base_url + self.filter_config
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        payload = response.content
        status = response.status_code
        if status == requests.codes.ok:
            return status, payload
        else:
            return response.content

    def get_network_sets(self):
        networksetListing = []
        url = self.rest_session.base_url + self.get_networks
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            payload = json.loads(response.content)
            for i in payload:
                networksetListing.append(i["id"])
            return status, networksetListing
        else:
            return response.content

    def set_filter_config(self):
        status, payload = self.get_filter_config()
        status, networksets = self.get_network_sets()

        if status == requests.codes.ok:
            resp = json.loads(payload)
            print(resp.keys())
            if "configMap" in resp.keys():
                for i in networksets:
                    nscreation = {"enabled": True,
                                  "networkSetId": i}
                    resp["configMap"]["1"]["networkSetFilter"].append(nscreation)
                    resp["configMap"]["1"]["enabled"] = True

            if "advancedConfig" in resp.keys():
                resp["advancedConfig"]["processingCycleTime"] = 15

            data = json.dumps(resp, indent=4)
            url = self.rest_session.base_url + self.filter_config
            headers = self.rest_session.headers
            response = self.rest_call.post_query(url=url, headers=headers, data=data, verify=False)
            if status == requests.codes.ok:
                return status
            else:
                return response.content

    def set_deny_policy(self):
        url = self.rest_session.base_url + self.deny_policy
        headers = self.rest_session.headers
        parameters = {"action": "DENY"}
        response = self.rest_call.put_query(url=url, headers=headers, params=parameters, verify=False)
        status = response.status_code
        return status

    def set_permit_policy(self):
        url = self.rest_session.base_url + self.deny_policy
        headers = self.rest_session.headers
        parameters = {"action": "PERMIT"}
        response = self.rest_call.put_query(url=url, headers=headers, params=parameters, verify=False)
        status = response.status_code
        return status

    def get_sequence_application_instance(self):
        url = self.rest_session.base_url + self.sequence_apps
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            payload = json.loads(response.content)
            return payload, status

    def get_individual_application_instance(self, appId):
        url = self.rest_session.base_url + self.app_instance + "/" + str(appId)
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            payload = json.loads(response.content)
            return payload, status
        else:
            return response.content

    # Function is retriving the sequence IDs and then implementing them
    def implement_individual_applications(self):
        apps_done =[]
        headers = self.rest_session.headers
        sequence, status = self.get_sequence_application_instance()
        if status == requests.codes.ok:
            sequence2 = sequence
            print(sequence2)
            if not sequence2:
                return False, "No Apps to implement"
        else:
            return False, "Unable to get sequence"
        for i in sequence2:
            app,status = self.get_individual_application_instance(i)
            url = self.rest_session.base_url + self.app_instance + "/" + str(i) + "/" + "implement"
            data2 = app
            data2["status"] = "VERIFIED"
            # Testing notifs
            data = json.dumps(data2,indent=4)
            print(data)
            response = self.rest_call.post_query(url=url, headers=headers, data=data, verify=False)
            status = response.status_code
            if status == requests.codes.ok:
                print(response.content)
                print("Application ID that is implemented: %d", i)
                apps_done.append(i)
            else:
                print(response.content)
                print(response.status_code)
                print("Application that failed to be implemented is %d", i)
                if apps_done:
                    print("Applications that are implemented are %s" % apps_done)
                return response.status_code
        acl_proposed = self.get_total_acl_proposed()
        acl_policy = self.get_acl_rules_policy()
        if acl_policy == acl_proposed:
            return status, "Applications are implemented %s" % apps_done
        else:
            return status, "ACL numbers are not matching check back again"


    def get_last_hit_acl_rule(self):
        url = self.rest_session.base_url + self.last_hit_rule
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        lasthitrule = json.loads(response.content)
        return lasthitrule

    def get_violations(self):
        starttime_human, timestamp = self.get_forward_testing_time()
        ruleid = self.get_last_hit_acl_rule()
        url = self.rest_session.base_url + self.get_violations_api + "/" + str(ruleid) + "/" + str(timestamp)
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        violations = json.loads(response.content)
        if response.status_code == requests.codes.ok:
            return response.status_code, violations
        else:
            return response.status_code, response.content

    def add_all_violations_aclPolicy(self):
        status_code, all_violations = self.get_violations()
        if status_code == requests.codes.ok:
            print(all_violations)
            for i in all_violations:
                rig = {}
                if i['srcRG']  == 0:
                    i["srcRGName"] ='ANY'
                if i['destRG'] == 0:
                    i["destRGName"] = 'ANY'
                # rule = self.acl_caller.get_aclrule_ruleid(str(i["ruleId"]))
                # rule = json.loads(rule)
                rig["action"] = "PERMIT"

                rig["name"] = str(i["srcRGName"]) + str(i["destRGName"]) + str(i["protocolName"]) + str(i["destPort"])
                rig["destinationResourceGroupList"] = [str(i["destRG"])]
                rig["sourceResourceGroupList"] = [str(i["srcRG"])]
                rig["destinationPortRanges"] = i["destPort"]
                rig["destinationProtocol"] = i["protocolName"]
                rig["enabled"] =True
                rig["orderNum"] = 1
                data = [rig]
                data = json.dumps(data, indent=4)
                params = {
                    "aclPolicyId": i["aclPolicyId"]
                }
                print(data)
                url = self.rest_session.base_url + self.create_acl_rule
                headers = self.rest_session.headers
                response = self.rest_call.put_query(url=url, headers=headers, data=data, verify=False, params=params)
                print(response.status_code)
                print(response.content)
                # if response.status_code == requests.codes.ok:
                #   print(response.status_code)
                # else:
                #    print(response.status_code, response.content)
        return response.status_code

    def get_cloud_id(self):
        url = self.rest_session.base_url + self.get_all_cloud_listing
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, verify=False)
        clouds = json.loads(response.content)
        return clouds

    def set_flow_logs(self,prereq):
        with open(prereq) as f:
            prereq = yaml.safe_load(f)

        if 'AWS' in prereq.keys():
            for i in prereq["AWS"]:
                cloudname = i["InfraName"]
                listing = self.get_cloud_id()
                for clouds in listing:
                    if clouds["name"] == cloudname:
                        cloudid = clouds["id"]
                        flow_aws = {
                                "accessKey": i["AccessKey"],
                                "region": i["Region"],
                                "s3BucketName": i["s3BucketName"],
                                "secretKey": i["SecretKey"]
                            }
                        payload = {
                            "aws": flow_aws,
                            "eventsFileEnabled": True,
                            "infraId": cloudid,
                            "startTime": int(time.time())
                        }
                        data = json.dumps(payload)
                        url = self.rest_session.base_url + self.post_aws_flow_log
                        headers = self.rest_session.headers
                        response = self.rest_call.post_query(url=url, headers=headers, data=data, timeout=400, verify=False)
                        status = response.status_code
                        if status == requests.codes.ok:
                            url = self.rest_session.base_url + self.test_aws_flow_connection
                            response = self.rest_call.post_query(url=url, headers=headers, data=flow_aws, timeout=400,
                                                                 verify=False)
                            status = response.status_code
                            if status == requests.codes.ok:
                                return status
                            else:
                                return response.content
                        else:

                            return response.content

    def applications_resource_group(self):
        url = self.rest_session.base_url + self.resource_group
        headers = self.rest_session.headers
        response = self.rest_call.get_query(url=url, headers=headers, timeout=10, verify=False)
        status = response.status_code
        if status == requests.codes.ok:
            resource_groups = response.content
            return status, resource_groups
        else:
            return status, response.content

    def get_application_vuln(self):
        headers = self.rest_session.headers
        sequence2 =[]
        summary, detailed_summary = self.app_summary()
        detailed_summary2 = detailed_summary["All Applications"]
        for i in detailed_summary2:
            sequence2.append(i["id"])
        for i in sequence2:
            url = self.rest_session.base_url + "applications/instance/" + str(i) + "/vulndetails"
            response = self.rest_call.get_query(url=url, headers=headers, timeout=10, verify=False)
            status = response.status_code
            if status == requests.codes.ok:
                content2 = response.content
                content = json.loads(content2)
                if content:
                    counter_critical = 0
                    counter_high =0
                    vuln_seen_critical =[]
                    vuln_seen_high =[]
                    for tt in content:
                        if tt["severity"] == "Critical":
                            counter_critical+=1
                            print(tt["name"])
                            vuln_seen_critical.append(tt["name"])
                        if tt["severity"] == "High":
                            counter_high+=1
                            print(tt["name"])
                            vuln_seen_high.append(tt["name"])
                    for jk in detailed_summary2:
                        if jk["id"] == i:
                            if "Critical" in jk["vulnerabilitySeverityMap"].keys():
                                if jk["vulnerabilitySeverityMap"]["Critical"] == counter_critical:
                                    print("Critical number checked against GM")
                                    print("%s critical vuln found " % counter_critical)
                                else:
                                    return False, "Critical number of apps not matching on application - %s" % jk["applicationName"]
                            if "High" in jk["vulnerabilitySeverityMap"].keys():
                                if jk["vulnerabilitySeverityMap"]["High"] == counter_high:
                                    print("Critical number checked against GM")
                                    print("%s high vuln found " % counter_high)
                                else:
                                    return False, "Critical number of apps not matching on application - %s" % jk["applicationName"]
                else:
                    print("App has no known vulnerabilities")
            else:
                return status,response.content

        return status,"All Apps vuln checked"

if __name__ == "__main__":
    pass
