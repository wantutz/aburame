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
#
# VPC

# standard library

# 3rd party library

# shieldx library

class VPC(object):
    def __init__(self, ec2_client=None):
        self.ec2_client = ec2_client

    def create_vpc(self, cidr_block):
        return self.ec2_client.create_vpc(
            CidrBlock = cidr_block
        )

    def delete_vpc(self, vpc_id):
        return self.ec2_client.delete_vpc(
            VpcId = vpc_id
        )

    def create_tags(self, resource_id, key, value):
        return self.ec2_client.create_tags(
            Resources = [resource_id],
            Tags = [
                {
                    "Key": key,
                    "Value": value
                }
            ]
        )

    def create_internet_gateway(self):
        return self.ec2_client.create_internet_gateway()

    def attach_igw_to_vpc(self, igw_id, vpc_id):
        return self.ec2_client.attach_internet_gateway(
            InternetGatewayId = igw_id,
            VpcId =  vpc_id
        )

    def describe_vpc_by_id(self, vpc_id):
        return self.ec2_client.describe_vpcs(
            VpcIds = [
                vpc_id,
            ]
        )

    def describe_vpc_by_filter(self, key, value):
        return self.ec2_client.describe_vpcs(
            Filters = [
                {
                    "Name": key,
                    "Values": [
                        value,
                    ]
                }
            ]
        )

    def describe_route_tables_by_filter(self, key, value):
        return self.ec2_client.describe_route_tables(
            Filters = [
                {
                    "Name": key,
                    "Values": [
                        value,
                    ]
                }
            ]
        )

    def describe_igw_by_filter(self, key, value):
        return self.ec2_client.describe_internet_gateways(
            Filters = [
                {
                    "Name": key,
                        "Values": [
                        value,
                    ]
                }
            ]
        )

    def create_subnet(self, vpc_id, cidr_block):
        return self.ec2_client.create_subnet(
            VpcId = vpc_id,
            CidrBlock = cidr_block
        )

    def describe_subnet_by_filter(self, key, value):
        return self.ec2_client.describe_subnets(
            Filters = [
                {
                    "Name": key,
                    "Values": [
                        value,
                    ]
                }
            ]
        )

    def create_public_route_table(self, vpc_id):
        return self.ec2_client.create_route_table(
            VpcId = vpc_id,
        )

    def create_igw_route_to_public_route_table(self, route_table_id, igw_id):
        return self.ec2_client.create_route(
            RouteTableId = route_table_id,
            GatewayId = igw_id,
            DestinationCidrBlock = "0.0.0.0/0"
        )

    def associate_subnet_with_route_table(self, route_table_id, subnet_id):
        return self.ec2_client.associate_route_table(
            RouteTableId = route_table_id,
            SubnetId = subnet_id
        )

    def allow_auto_assign_ip_addresses_for_subnet(self, subnet_id):
        return self.ec2_client.modify_subnet_attribute(
            MapPublicIpOnLaunch = {"Value": True},
            SubnetId = subnet_id
        )
