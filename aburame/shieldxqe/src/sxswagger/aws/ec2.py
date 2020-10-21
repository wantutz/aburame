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
# EC2

# standard library

# 3rd party library

# shieldx library

class EC2(object):
    def __init__(self, ec2_client=None):
        self.ec2_client = ec2_client

    def create_key_pair(self, key_name):
        return self.ec2_client.create_key_pair(
            KeyName = key_name
        )

    def describe_key_pair_by_filter(self, key, value):
        return self.ec2_client.describe_key_pairs(
            Filters = [
                {
                    "Name": key,
                    "Values": [
                        value,
                    ]
                }
            ]
        )

    def create_security_group(self, group_name, description, vpc_id):
        return self.ec2_client.create_security_group(
            GroupName = group_name,
            Description = description,
            VpcId = vpc_id
        )

    def describe_security_group_by_filter(self, key, value):
        return self.ec2_client.describe_security_groups(
            Filters = [
                {
                    "Name": key,
                    "Values": [
                        value,
                    ]
                }
            ]
        )

    def add_inbound_rule_to_sg(self, security_group_id, ip_permissions):
        return self.ec2_client.authorize_security_group_ingress(
            GroupId = security_group_id,
            IpPermissions = ip_permissions
        )

    def launch_ec2_instance(self, image_id, key_name, min_count, max_count,
        instance_type, security_group_id, subnet_id, user_data
    ):
        return self.ec2_client.run_instances(
            ImageId = image_id,
            KeyName = key_name,
            MinCount = min_count,
            MaxCount = max_count,
            InstanceType = instance_type,
            SecurityGroupIds = [security_group_id],
            SubnetId = subnet_id,
            UserData = user_data
        )

    def describe_ec2_instances(self):
        return self.ec2_client.describe_instances()

    def modify_ec2_instance(self, instance_id):
        return self.ec2_client.modify_instance_attribute(
            InstanceId = instance_id,
            DisableApiTermination = {"Value": True}
        )

    def stop_ec2_instance(self, instance_id):
        return self.ec2_client.stop_instances(
            InstanceIds = [instance_id]
        )

    def start_ec2_instance(self, instance_id):
        return self.ec2_client.start_instances(
            InstanceIds = [instance_id]
        )

    def terminate_ec2_instance(self, instance_id):
        return self.ec2_client.terminate_instances(
            InstanceIds = [instance_id]
        )
