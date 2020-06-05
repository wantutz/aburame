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
# Data plane management

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall


class DataplaneManagement(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # fetched data
        self.data = None

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs specific to Resource group and Network set
        self.chassis_list_url = "chassislist"
        self.chassis_redeploy_id = "chassis/"
        self.network_set_insertionstaging_elements = "chassis/insertionstagingelements"
        self.network_set_chassis_bulkinsertion = "chassisbulkinsertion"

    def get_chassis_list(self):
        dp_list = None

        # Craft the URL
        url = self.rest_session.base_url + self.chassis_list_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        dp_list = list(response.json())
        return dp_list

    def get_redeploy_chassisid(self,dp_id):
        job_id = None

        chassisid = str(dp_id)

        # Craft the URL
        url = self.rest_session.base_url + self.chassis_redeploy_id + chassisid + "/redeploy"

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url = url,
            verify=False,
            headers = headers
        )
        job_id = response.json()
        return job_id

    def ns_insertionstaging_elements(self, ns_id, nsname, chassis_id, insertion_type):
        ns_staged = False
        insert_type = insertion_type.upper()

        payload = [
            {
                "id": 19,
                "name": "NSET-1-PG63-200",
                "infraId": 1,
                "type": "NETWORK_SET",
                "chassisSubscriptionMap": {
                    "2": {
                        "subscription": {
                            "chassisId": 2,
                            "insertable": True,
                            "insertionType": "SEGMENTATION",
                            "markForDeletion": False,
                            "precedence": 1,
                            "resourceGroupId": 19
                        }
                    }
                },
                "status": "STAGING",
                "action": "EDIT"
            }
        ]

        for i in payload:
            if i["type"] == "NETWORK_SET":
                i["id"] = ns_id
                i["name"] = nsname
                i["chassisSubscriptionMap"]["2"]["subscription"]["chassisId"] = chassis_id
                i["chassisSubscriptionMap"]["2"]["subscription"]["insertionType"] = insert_type
                i["chassisSubscriptionMap"]["2"]["subscription"]["resourceGroupId"] = ns_id
                data = json.dumps(payload)

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.network_set_insertionstaging_elements

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
                ns_staged = True
                self.logger.info("New network set staged for insertion")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)
        return ns_staged

    def ns_chassis_bulkinsertion(self, ns_id, chassis_id, insertion_type):
        ns_insert = False
        insert_type = insertion_type.upper()

        payload = [
            {
                "id": 22,
                "action": "EDIT",
                "infraId": 1,
                "status": "STAGING",
                "type": "NETWORK_SET",
                "chassisSubscriptionMap": {
                    "2": {
                        "subscription": {
                            "chassisId": 2,
                            "insertable": True,
                            "insertionType": "SEGMENTATION",
                            "markForDeletion": False,
                            "precedence": 1,
                            "resourceGroupId": 22
                        }
                    }
                }
            }
        ]

        for i in payload:
            if i["type"] == "NETWORK_SET":
                i["id"] = ns_id
                i["chassisSubscriptionMap"]["2"]["subscription"]["chassisId"] = chassis_id
                i["chassisSubscriptionMap"]["2"]["subscription"]["insertionType"] = insert_type
                i["chassisSubscriptionMap"]["2"]["subscription"]["resourceGroupId"] = ns_id
                data = json.dumps(payload)
        try:
            # Craft the URL
            url = self.rest_session.base_url + self.network_set_chassis_bulkinsertion

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
                ns_insert = True
                self.logger.info("New network set submitted for insertion")
                ns_jid = list(response.json())
                for nsjid in ns_jid:
                    if nsjid["type"] == 'NETWORK_SET':
                        ns_jobid = int(nsjid["chassisSubscriptionMap"]["2"]["jobId"])
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return ns_jobid


if __name__ == "__main__":
    pass
