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
# Cloud Management

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class CloudManagement(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URL specific to this Module
        self.infras_url = "infras"
        self.resource_group_url = "infras/resourcegroup"
        self.resource_groups_url = "infras/resourcegroups"

        self.ip_pool_url = "ippool"

        # URL separator
        self.sep_url = "/"

    def create_cloud(self, cloud_info):
        # Cloud ID
        cloud_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url

        # Headers
        headers = self.rest_session.headers

        # Data
        data = json.dumps(cloud_info)

        # Create Infra Connector - POST
        response = self.rest_call.post_query(
                       url = url,
                       data = data,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            cloud_id = int(response.json())
        else:
            pass

        return cloud_id

    def delete_cloud(self, cloud_id):
        # Craft the URL
        url = self.rest_session.base_url + self.infras_url +  self.sep_url + str(cloud_id)

        # Headers
        headers = self.rest_session.headers

        # Delete Infra Connector - DELETE
        response = self.rest_call.delete_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            return True
        else:
            return False

    def get_cloud_objects(self, cloud_id):
        cloud_objects = None

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url +  self.sep_url + str(cloud_id) + self.sep_url + "objects"

        # Headers
        headers = self.rest_session.headers

        # Infra Objects - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            cloud_objects = dict(response.json())
        else:
            return False

        return cloud_objects

    def create_cloud_infra(self, **cloud_info):
        # Infra ID
        infra_id = None

        # Verify necessary info are defined
        try:
            # Verify cloud info is not None
            if not all([cloud_info["cloud_type"],
                        cloud_info["username"],
                        cloud_info["password"],
                   ]):
                self.logger.error("One of the cloud info is None.")
                return infra_id
            else:
                # Proceed with cloud infra creation
                pass
        except KeyError as e:
            self.logger.error("Missing necessary cloud information.")
            return infra_id

        # Verify cloud information
        if cloud_info["cloud_type"] == "VMWARE":
            self.logger.info("Cloud Type: {}".format(cloud_info["cloud_type"]))
        elif cloud_info["cloud_type"] == "AWS":
            self.logger.info("Cloud Type: {}".format(cloud_info["cloud_type"]))
        elif cloud_info["cloud_type"] == "MS Azure":
            self.logger.info("Cloud Type: {}".format(cloud_info["cloud_type"]))
        else:
            self.logger.error("Cloud Type: {}".format(cloud_info["cloud_type"]))

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url

        # Headers
        headers = self.rest_session.headers

        # Create Infra Connector - POST

        # Convert response to expected data

        return infra_id

    def get_cloud_infra(self):
        # Cloud list
        cloud_list = None

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url

        # Headers
        headers = self.rest_session.headers

        # Get Cloud Infras - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            cloud_list = list(response.json())
        else:
            pass

        return cloud_list

    def get_cloud_infra_by_name(self, cloud_name):
        # Cloud (Infra Connectors)
        cloud_list = self.get_cloud_infra()

        for cloud in cloud_list:
            if cloud_name == cloud["name"]:
                return cloud

        return None

    def update_cloud_infra(self, cloud_info):
        is_updated = False

        # Craft the URL
        url = self.rest_session.base_url + self.infras_url

        # Payload
        data = json.dumps(cloud_info)

        # Headers
        headers = self.rest_session.headers

        # Update Cloud Infra - PUT
        response = self.rest_call.put_query(
                       url = url,
                       data = data,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_updated = True
        else:
            pass

        return is_updated

    def create_resource_group(self, resource_group):
        rg_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.resource_group_url

        # Headers
        headers = self.rest_session.headers

        # Payload
        data = json.dumps(resource_group)

        # Create Resource Group - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            rg_id, _ = list(response.json())
        else:
            pass

        return rg_id

    def get_resource_groups(self):
        resource_groups = []

        # Craft the URL
        url = self.rest_session.base_url + self.resource_groups_url

        # Headers
        headers = self.rest_session.headers

        # Get Resource Groups - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            resource_groups = list(response.json())
        else:
            pass

        return resource_groups

    def get_resource_group_by_name(self, rg_name):
        resource_group = None

        # Craft the URL
        url = self.rest_session.base_url + self.resource_groups_url

        # Headers
        headers = self.rest_session.headers

        # Get Resource Groups - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            for rg in list(response.json()):
                if rg["name"] == rg_name:
                    resource_group = rg
                    break
        else:
            pass

        return resource_group

    def remove_resource_group_by_name(self, rg_name):
        is_deleted = False

        rg = self.get_resource_group_by_name(rg_name)

        if rg is not None:
            # Craft the URL
            url = self.rest_session.base_url + self.resource_group_url + self.sep_url + str(rg["id"])

            # Headers
            headers = self.rest_session.headers

            # Delete Resource Groups - DELETE
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
        else:
            pass

        return is_deleted

    def create_ip_pool(self, ip_pool):
        ip_pool_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.ip_pool_url

        # Data
        data = json.dumps(ip_pool)

        # Headers
        headers = self.rest_session.headers

        # Create IP Pool - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            ip_pool_id = int(response.text)
        else:
            pass

        return ip_pool_id

    def get_ip_pools(self, infra_id):
        ip_pools = []

        # Craft the URL
        url = self.rest_session.base_url + str(infra_id) + self.sep_url + self.ip_pool_url

        # Headers
        headers = self.rest_session.headers

        # Get IP Pools - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            ip_pools = list(response.json())
        else:
            pass

        return ip_pools

    def get_ip_pool_by_name(self, infra_id, ip_pool_name):
        ip_pools = self.get_ip_pools(infra_id)

        for ip_pool in ip_pools:
            if ip_pool["name"] == ip_pool_name:
                return ip_pool
            else:
                continue

        return None

    def delete_ip_pool_by_name(self, infra_id, ip_pool_name):
        is_deleted = False

        ip_pools = self.get_ip_pools(infra_id)

        ip_pool_id = None

        for ip_pool in ip_pools:
            if ip_pool["name"] == ip_pool_name:
                ip_pool_id = ip_pool["id"]
                break
            else:
                continue

        if ip_pool_id is not None:
            # Craft URL
            url = self.rest_session.base_url + self.ip_pool_url + self.sep_url + str(ip_pool_id)

            # Headers
            headers = self.rest_session.headers

            # Delete IP Pool - DELETE
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
        else:
            # NOOP
            pass

        return is_deleted

if __name__ == "__main__":
    pass
