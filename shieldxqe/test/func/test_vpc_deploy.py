import pytest
import json
import os
import time
import threading

# shieldx - sxapi library
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

from sxswagger.aws.vpc import VPC
from sxswagger.aws.ec2 import EC2

from boto3.s3.transfer import TransferConfig

@pytest.mark.aws_vpc
@pytest.mark.parametrize("vpc_json", [
        ("vpc1.json"),
    ]
)
def test_create_vpc(
    ec2_client, vpc_json,
    datadir, shieldx_constants, shieldx_logger
):
    vpc = VPC(ec2_client=ec2_client)
    config_reader = CCR()

    # Read VPC Info
    vpc_filename = str((datadir/vpc_json).resolve())
    vpc_info = dict(config_reader.read_json_config(vpc_filename))

    # Describe VPCs
    vpc_cidr_block = vpc_info["cidr_block"]
    vpc_response = vpc.describe_vpc_by_filter("cidr", vpc_cidr_block)
    shieldx_logger.info("Describe VPC: {}".format(vpc_response))

    # Fetch target VPC
    target_vpc = get_target("CidrBlock", vpc_cidr_block, vpc_response["Vpcs"])

    # Work with existing VPC
    if not target_vpc["found"]:
        # Create VPC
        vpc_response = vpc.create_vpc(vpc_cidr_block)
        shieldx_logger.info("Create VPC: {}".format(vpc_response))

        # Fetch VPC ID from create VPC response
        vpc_id = vpc_response["Vpc"]["VpcId"]
        vpc_info["vpc_id"] = vpc_id
        vpc_name = vpc_info["vpc_name"]

        shieldx_logger.info("VPC Name: {}".format(vpc_name))
        shieldx_logger.info("VPC ID: {}".format(vpc_id))

        # Tag the VPC
        tag_response = vpc.create_tags(vpc_id, vpc_name)
        shieldx_logger.info("Tag VPC: {}".format(tag_response))

        # Create Internet gateway
        igw_response = vpc.create_internet_gateway()
        shieldx_logger.info("Create IGW: {}".format(igw_response))
        igw_id = igw_response["InternetGateway"]["InternetGatewayId"]
        igw_name = vpc_info["internet_gateway"]["name"]
        vpc_info["internet_gateway"]["id"] = igw_id

        shieldx_logger.info("IGW Name: {}".format(igw_name))
        shieldx_logger.info("IGW ID: {}".format(igw_id))

        # Tag the IGW
        tag_response = vpc.create_tags(igw_id, igw_name)
        shieldx_logger.info("Tag IGW: {}".format(tag_response))

        # Attach the Internet gateway
        attach_response = vpc.attach_igw_to_vpc(igw_id, vpc_id)
        shieldx_logger.info("Attach: {}".format(attach_response))

        # Write VPC Info - for debugging
        shieldx_logger.info("VPC Info: {}".format(vpc_info))
        shieldx_logger.info("VPC location: {}".format(vpc_filename))
        config_reader.write_json_config(vpc_info, vpc_filename)
    else:
        # VPC with given CIDR block already exist, skip create
        shieldx_logger.warning("VPC Already Exist: {}".format(target_vpc["target"]))

@pytest.mark.aws_vpc
@pytest.mark.parametrize("vpc_json", [
        ("vpc1.json"),
    ]
)
def test_create_public_subnet(
    ec2_client, vpc_json,
    datadir, shieldx_constants, shieldx_logger
):
    vpc = VPC(ec2_client=ec2_client)
    config_reader = CCR()

    # Read VPC Info
    vpc_filename = str((datadir/vpc_json).resolve())
    vpc_info = dict(config_reader.read_json_config(vpc_filename))

    # Describe VPCs
    vpc_cidr_block = vpc_info["cidr_block"]
    vpc_response = vpc.describe_vpc_by_filter("cidr", vpc_cidr_block)
    shieldx_logger.info("Describe VPC: {}".format(vpc_response))

    # Fetch target VPC
    target_vpc = get_target("CidrBlock", vpc_cidr_block, vpc_response["Vpcs"])

    # If target VPC is found, proceed creating public subnet
    if target_vpc["found"]:
        # Get VPC Name and ID
        vpc_target = target_vpc["target"]
        shieldx_logger.info("Found matching VPC: {}".format(vpc_target))

        vpc_id = vpc_target["VpcId"]
        vpc_name = vpc_info["vpc_name"]

        shieldx_logger.info("VPC Name: {}".format(vpc_name))
        shieldx_logger.info("VPC ID: {}".format(vpc_id))

        for public_subnet in vpc_info["public_subnet"]:
            # Create Public Subnet
            create_subnet_response = vpc.create_subnet(vpc_id, public_subnet["address"])
            public_subnet["id"] = create_subnet_response["Subnet"]["SubnetId"]

            # Name Public Subnet
            vpc.create_tags(public_subnet["id"], public_subnet["name"])

            shieldx_logger.info("Create Public Subnet Response: {}".format(create_subnet_response))
            shieldx_logger.info("Public Subnet: {}".format(public_subnet))

        # Create Public Route Table
        create_route_table_response = vpc.create_public_route_table(vpc_id)
        shieldx_logger.info("Create Public Route Table: {}".format(create_route_table_response))

        # Get Route Table ID
        route_table_id = create_route_table_response["RouteTable"]["RouteTableId"]
        vpc_info["public_route_table"]["id"] = route_table_id

        # Get IGW ID
        describe_igw_response = vpc.describe_igw_by_filter("attachment.vpc-id", vpc_id)
        shieldx_logger.info("Describe IGW Response: {}".format(describe_igw_response))
        igw = describe_igw_response["InternetGateways"][0]
        igw_id = igw["InternetGatewayId"]
        vpc_info["internet_gateway"]["id"] = igw_id

        shieldx_logger.info("Route Table ID: {}".format(route_table_id))
        shieldx_logger.info("Internet Gateway ID: {}".format(igw_id))

        # Create Route to IGW
        create_route_response = vpc.create_igw_route_to_public_route_table(route_table_id, igw_id)
        shieldx_logger.info("Create Route to IGW: {}".format(create_route_response))

        for public_subnet in vpc_info["public_subnet"]:
            # Associate Public Subnet with Route Table
            associate_subnet_response = vpc.associate_subnet_with_route_table(route_table_id, public_subnet["id"])
            shieldx_logger.info("Associate Public subnet with Route Table: {}".format(associate_subnet_response))

            # Allow auto-assign public IP Address for subnet
            vpc.allow_auto_assign_ip_addresses_for_subnet(public_subnet["id"])

        # Write VPC Info - for debugging
        shieldx_logger.info("VPC Info: {}".format(vpc_info))
        shieldx_logger.info("VPC location: {}".format(vpc_filename))
        config_reader.write_json_config(vpc_info, vpc_filename)
    else:
        # VPC not found, create VPC first
        shieldx_logger.warning("VPC not found.")

@pytest.mark.aws_vpc
@pytest.mark.parametrize("vpc_json", [
        ("vpc1.json"),
    ]
)
def test_create_private_subnet(
    ec2_client, vpc_json,
    datadir, shieldx_constants, shieldx_logger
):
    vpc = VPC(ec2_client=ec2_client)
    config_reader = CCR()

    # Read VPC Info
    vpc_filename = str((datadir/vpc_json).resolve())
    vpc_info = dict(config_reader.read_json_config(vpc_filename))

    # Describe VPCs
    vpc_cidr_block = vpc_info["cidr_block"]
    vpc_response = vpc.describe_vpc_by_filter("cidr", vpc_cidr_block)
    shieldx_logger.info("Describe VPC: {}".format(vpc_response))

    # Fetch target VPC
    target_vpc = get_target("CidrBlock", vpc_cidr_block, vpc_response["Vpcs"])

    # If target VPC is found, proceed creating private subnet
    if target_vpc["found"]:
        # Get VPC Name and ID
        vpc_target = target_vpc["target"]
        shieldx_logger.info("Found matching VPC: {}".format(vpc_target))

        vpc_id = vpc_target["VpcId"]
        vpc_name = vpc_info["vpc_name"]

        shieldx_logger.info("VPC Name: {}".format(vpc_name))
        shieldx_logger.info("VPC ID: {}".format(vpc_id))

        for private_subnet in vpc_info["private_subnet"]:
            # Create Private Subnet
            create_subnet_response = vpc.create_subnet(vpc_id, private_subnet["address"])
            private_subnet["id"] = create_subnet_response["Subnet"]["SubnetId"]

            # Name Private Subnet
            vpc.create_tags(private_subnet["id"], private_subnet["name"])

            shieldx_logger.info("Create Private Subnet Response: {}".format(create_subnet_response))
            shieldx_logger.info("Private Subnet: {}".format(private_subnet))

        # Write VPC Info - for debugging
        shieldx_logger.info("VPC Info: {}".format(vpc_info))
        shieldx_logger.info("VPC location: {}".format(vpc_filename))
        config_reader.write_json_config(vpc_info, vpc_filename)
    else:
        # VPC not found, create VPC first
        shieldx_logger.warning("VPC not found.")

@pytest.mark.aws_ec2
@pytest.mark.parametrize("vpc_json, ec2_json", [
        ("vpc1.json", "ec2_public_instance1.json"),
    ]
)
def test_launch_public_ec2_instance(
    ec2_client, vpc_json, ec2_json,
    datadir, shieldx_constants, shieldx_logger
):
    # Init clients
    vpc = VPC(ec2_client=ec2_client)
    ec2 = EC2(ec2_client=ec2_client)
    config_reader = CCR()

    # Read VPC Info
    vpc_filename = str((datadir/vpc_json).resolve())
    vpc_info = dict(config_reader.read_json_config(vpc_filename))

    # Read EC2 Info
    ec2_filename = str((datadir/ec2_json).resolve())
    ec2_info = dict(config_reader.read_json_config(ec2_filename))

    # Describe VPCs
    vpc_cidr_block = vpc_info["cidr_block"]
    vpc_response = vpc.describe_vpc_by_filter("cidr", vpc_cidr_block)
    shieldx_logger.info("Describe VPC: {}".format(vpc_response))

    # Fetch target VPC
    target_vpc = get_target("CidrBlock", vpc_cidr_block, vpc_response["Vpcs"])

    # If target VPC is found, proceed creating public ec2 launch
    if target_vpc["found"]:
        # Get VPC Name and ID
        vpc_target = target_vpc["target"]
        shieldx_logger.info("Found matching VPC: {}".format(vpc_target))

        vpc_id = vpc_target["VpcId"]
        vpc_name = vpc_info["vpc_name"]

        shieldx_logger.info("VPC Name: {}".format(vpc_name))
        shieldx_logger.info("VPC ID: {}".format(vpc_id))

        # Check if key pair exist
        key_pair_name = ec2_info["keypair_name"]
        key_pair_response = ec2.describe_key_pair_by_filter("key-name", key_pair_name)
        target_key_pair = get_target("KeyName", key_pair_name, key_pair_response["KeyPairs"])

        # If key pair is missing, create it first
        if not target_key_pair["found"]:
            key_pair_response = ec2.create_key_pair(key_pair_name)
            shieldx_logger.info("Key Pair Created: {}".format(key_pair_response))
        else:
            # Key pair already exist, proceed and use it
            pass

        # Check if Security Group exist
        public_security_group_id = None
        public_security_group_name = ec2_info["security_group"]["name"]
        public_security_group_desc = ec2_info["security_group"]["desc"]
        security_group_response = ec2.describe_security_group_by_filter("group-name", public_security_group_name)
        target_security_group = get_target("GroupName", public_security_group_name, security_group_response["SecurityGroups"])

        # If target security group is missing, create it first
        if not target_security_group["found"]:
            # Create a Security Group
            public_sg_response = ec2.create_security_group(public_security_group_name, public_security_group_desc, vpc_id)
            public_security_group_id = public_sg_response["GroupId"]
            ec2_info["security_group"]["id"] = public_security_group_id

            shieldx_logger.info("Security Group: {}".format(ec2_info["security_group"]))

            # IP Permissions
            ip_permissions = ec2_info["ip_permissions"]

            # Add inbound rule to security group - take from ec2_instance1.json
            ec2.add_inbound_rule_to_sg(public_security_group_id, ip_permissions)
        else:
            # Security Group Already exist, proceed and use it
            public_security_group_id = target_security_group["target"]["GroupId"]

        # Image ID and Instance Type
        image_id = ec2_info["image_id"]
        instance_type = ec2_info["instance_type"]

        # User Data - Startup script for EC2 instance
        startup_script = """
            #!/bin/bash
            yum update -y
            amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
            yum install -y httpd mariadb-server
            systemctl start httpd
            systemctl enable httpd
            usermod -a -G apache ec2-user
            chown -R ec2-user:apache /var/www
            chmod 2775 /var/www
            echo "<html><body><h1>Hello <b>ShieldX</b></h1></body></html>" > /var/www/html/index.html
        """

        # EC2 CIDR block
        ec2_cidr_block = ec2_info["cidr_block"]
        subnets_response = vpc.describe_subnet_by_filter("cidr-block", ec2_cidr_block)
        target_subnet = get_target("CidrBlock", ec2_cidr_block, subnets_response["Subnets"])

        # If subnet exist, proceed and use it
        if target_subnet["found"]:
            # Subnet ID
            subnet_id = target_subnet["target"]["SubnetId"]

            # Launch EC2 instance
            launch_ec2_response = ec2.launch_ec2_instance(image_id, key_pair_name, 1, 1, instance_type, public_security_group_id, subnet_id, startup_script)
            shieldx_logger.info("Launching EC2 Instance: {}".format(launch_ec2_response))
        else:
            # Public Subnet not found
            shieldx_logger.warning("Public subnet not found: {}".format(ec2_cidr_block))
    else:
        # VPC not found, create VPC first
        shieldx_logger.warning("VPC not found.")

@pytest.mark.aws_ec2
@pytest.mark.parametrize("vpc_json, ec2_json", [
        ("vpc1.json", "ec2_private_instance1.json"),
    ]
)
def test_launch_private_ec2_instance(
    ec2_client, vpc_json, ec2_json,
    datadir, shieldx_constants, shieldx_logger
):
    # Init clients
    vpc = VPC(ec2_client=ec2_client)
    ec2 = EC2(ec2_client=ec2_client)
    config_reader = CCR()

    # Read VPC Info
    vpc_filename = str((datadir/vpc_json).resolve())
    vpc_info = dict(config_reader.read_json_config(vpc_filename))

    # Read EC2 Info
    ec2_filename = str((datadir/ec2_json).resolve())
    ec2_info = dict(config_reader.read_json_config(ec2_filename))

    # Describe VPCs
    vpc_cidr_block = vpc_info["cidr_block"]
    vpc_response = vpc.describe_vpc_by_filter("cidr", vpc_cidr_block)
    shieldx_logger.info("Describe VPC: {}".format(vpc_response))

    # Fetch target VPC
    target_vpc = get_target("CidrBlock", vpc_cidr_block, vpc_response["Vpcs"])

    # If target VPC is not present, create
    if target_vpc["found"]:
        # Get VPC Name and ID
        vpc_target = target_vpc["target"]
        shieldx_logger.info("Found matching VPC: {}".format(vpc_target))

        vpc_id = vpc_target["VpcId"]
        vpc_name = vpc_info["vpc_name"]

        shieldx_logger.info("VPC Name: {}".format(vpc_name))
        shieldx_logger.info("VPC ID: {}".format(vpc_id))

        # Check if key pair exist
        key_pair_name = ec2_info["keypair_name"]
        key_pair_response = ec2.describe_key_pair_by_filter("key-name", key_pair_name)
        target_key_pair = get_target("KeyName", key_pair_name, key_pair_response["KeyPairs"])

        # If key pair is missing, create it first
        if not target_key_pair["found"]:
            key_pair_response = ec2.create_key_pair(key_pair_name)
            shieldx_logger.info("Key Pair Created: {}".format(key_pair_response))
        else:
            # Key pair already exist, proceed and use it
            pass

        # Check if Security Group exist
        private_security_group_id = None
        private_security_group_name = ec2_info["security_group"]["name"]
        private_security_group_desc = ec2_info["security_group"]["desc"]
        security_group_response = ec2.describe_security_group_by_filter("group-name", private_security_group_name)
        target_security_group = get_target("GroupName", private_security_group_name, security_group_response["SecurityGroups"])

        # If target security group is missing, create it first
        if not target_security_group["found"]:
            # Create a Security Group
            private_sg_response = ec2.create_security_group(private_security_group_name, private_security_group_desc, vpc_id)
            private_security_group_id = private_sg_response["GroupId"]
            ec2_info["security_group"]["id"] = private_security_group_id

            shieldx_logger.info("Security Group: {}".format(ec2_info["security_group"]))

            # IP Permissions - no access from the internet
            ip_permissions = ec2_info["ip_permissions"]

            # Add inbound rule to security group - take from ec2_instance1.json
            ec2.add_inbound_rule_to_sg(private_security_group_id, ip_permissions)
        else:
            # Security Group Already exist, proceed and use it
            private_security_group_id = target_security_group["target"]["GroupId"]

        # Image ID and Instance Type
        image_id = ec2_info["image_id"]
        instance_type = ec2_info["instance_type"]

        # User Data - Startup script for EC2 instance
        startup_script = """"""

        # EC2 CIDR block
        ec2_cidr_block = ec2_info["cidr_block"]
        subnets_response = vpc.describe_subnet_by_filter("cidr-block", ec2_cidr_block)
        target_subnet = get_target("CidrBlock", ec2_cidr_block, subnets_response["Subnets"])

        # If subnet exist, proceed and use it
        if target_subnet["found"]:
            # Subnet ID
            subnet_id = target_subnet["target"]["SubnetId"]

            # Launch EC2 instance
            launch_ec2_response = ec2.launch_ec2_instance(image_id, key_pair_name, 1, 1, instance_type, private_security_group_id, subnet_id, startup_script)
            shieldx_logger.info("Launching EC2 Instance: {}".format(launch_ec2_response))
        else:
            # Private Subnet not found
            shieldx_logger.warning("Private subnet not found: {}".format(ec2_cidr_block))
    else:
        # VPC not found, create VPC first
        shieldx_logger.warning("VPC not found.")

@pytest.mark.aws_ec2
@pytest.mark.parametrize("ec2_json", [
        ("ec2_public_instance1.json"),
    ]
)
def test_modify_public_ec2_attribute(
    ec2_client, ec2_json,
    datadir, shieldx_constants, shieldx_logger
):
    # Init clients
    ec2 = EC2(ec2_client=ec2_client)
    config_reader = CCR()

    # Read EC2 Info
    ec2_filename = str((datadir/ec2_json).resolve())
    ec2_info = dict(config_reader.read_json_config(ec2_filename))

    # Describe EC2 instances
    ec2_response = dict(ec2.describe_ec2_instances())
    reservations = list(ec2_response["Reservations"])
    shieldx_logger.info("Reservations Count: {}".format(len(reservations)))

    # Modify the public EC2 only
    public_security_group = ec2_info["security_group"]["name"]

    for reservation in reservations:
        instance_id = reservation["Instances"][0]["InstanceId"]
        state = reservation["Instances"][0]["State"]
        security_groups = reservation["Instances"][0]["SecurityGroups"]

        # Make the public EC2 instance immunte to API, or CLI termination
        # It can only be terminated by going to AWS Console
        # State - Code 16 = running
        # State - Code 48 = terminated
        if int(state["Code"]) == 16 and security_groups[0]["GroupName"] == public_security_group:
            shieldx_logger.info("Modify this EC2 instance: {}".format(instance_id))
            shieldx_logger.info("Modify this EC2 instance - State: {}".format(state))
            shieldx_logger.info("Modify this EC2 Instance - Security Groups: {}".format(security_groups))
            ec2.modify_ec2_instance(instance_id)
        else:
            shieldx_logger.warning("Skipping this EC2 instance - ID: {}".format(instance_id))
            shieldx_logger.warning("Skipping this EC2 instance - State: {}".format(state))
            shieldx_logger.warning("Skipping this EC2 instance - Security Groups: {}".format(security_groups))

@pytest.mark.aws_ec2
@pytest.mark.parametrize("ec2_json", [
        ("ec2_private_instance1.json"),
    ]
)
def test_start_private_ec2(
    ec2_client, ec2_json,
    datadir, shieldx_constants, shieldx_logger
):
    # Init clients
    ec2 = EC2(ec2_client=ec2_client)
    config_reader = CCR()

    # Read EC2 Info
    ec2_filename = str((datadir/ec2_json).resolve())
    ec2_info = dict(config_reader.read_json_config(ec2_filename))

    # Describe EC2 instances
    ec2_response = dict(ec2.describe_ec2_instances())
    reservations = list(ec2_response["Reservations"])
    shieldx_logger.info("Reservations Count: {}".format(len(reservations)))

    # Start the private EC2 instance
    private_security_group = ec2_info["security_group"]["name"]

    for reservation in reservations:
        instance_id = reservation["Instances"][0]["InstanceId"]
        state = reservation["Instances"][0]["State"]
        security_groups = reservation["Instances"][0]["SecurityGroups"]

        # Start the private EC2 instance
        if int(state["Code"]) != 48 and security_groups[0]["GroupName"] == private_security_group:
            shieldx_logger.info("Start this EC2 instance - ID: {}".format(instance_id))
            shieldx_logger.info("Start this EC2 instance - State: {}".format(state))
            shieldx_logger.info("Start this EC2 Instance - Security Groups: {}".format(security_groups))
            ec2.start_ec2_instance(instance_id)
        else:
            shieldx_logger.warning("Skipping this EC2 instance - ID: {}".format(instance_id))
            shieldx_logger.warning("Skipping this EC2 instance - State: {}".format(state))
            shieldx_logger.warning("Skipping this EC2 instance - Security Groups: {}".format(security_groups))

@pytest.mark.aws_ec2
@pytest.mark.parametrize("ec2_json", [
        ("ec2_private_instance1.json"),
    ]
)
def test_stop_private_ec2(
    ec2_client, ec2_json,
    datadir, shieldx_constants, shieldx_logger
):
    # Init clients
    ec2 = EC2(ec2_client=ec2_client)
    config_reader = CCR()

    # Read EC2 Info
    ec2_filename = str((datadir/ec2_json).resolve())
    ec2_info = dict(config_reader.read_json_config(ec2_filename))

    # Describe EC2 instances
    ec2_response = dict(ec2.describe_ec2_instances())
    reservations = list(ec2_response["Reservations"])
    shieldx_logger.info("Reservations Count: {}".format(len(reservations)))

    # Stop the private EC2 instance
    private_security_group = ec2_info["security_group"]["name"]

    for reservation in reservations:
        instance_id = reservation["Instances"][0]["InstanceId"]
        state = reservation["Instances"][0]["State"]
        security_groups = reservation["Instances"][0]["SecurityGroups"]

        # Stop the private EC2 instance
        if int(state["Code"]) != 48 and security_groups[0]["GroupName"] == private_security_group:
            shieldx_logger.info("Stop this EC2 instance - ID: {}".format(instance_id))
            shieldx_logger.info("Stop this EC2 instance - State: {}".format(state))
            shieldx_logger.info("Stop this EC2 Instance - Security Groups: {}".format(security_groups))
            ec2.stop_ec2_instance(instance_id)
        else:
            shieldx_logger.warning("Skipping this EC2 instance - ID: {}".format(instance_id))
            shieldx_logger.warning("Skipping this EC2 instance - State: {}".format(state))
            shieldx_logger.warning("Skipping this EC2 instance - Security Groups: {}".format(security_groups))

@pytest.mark.aws_ec2
@pytest.mark.parametrize("ec2_json", [
        ("ec2_private_instance1.json"),
    ]
)
def test_terminate_private_ec2(
    ec2_client, ec2_json,
    datadir, shieldx_constants, shieldx_logger
):
    # Init clients
    ec2 = EC2(ec2_client=ec2_client)
    config_reader = CCR()

    # Read EC2 Info
    ec2_filename = str((datadir/ec2_json).resolve())
    ec2_info = dict(config_reader.read_json_config(ec2_filename))

    # Describe EC2 instances
    ec2_response = dict(ec2.describe_ec2_instances())
    reservations = list(ec2_response["Reservations"])
    shieldx_logger.info("Reservations Count: {}".format(len(reservations)))

    # Terminate the private EC2 instance
    private_security_group = ec2_info["security_group"]["name"]

    for reservation in reservations:
        instance_id = reservation["Instances"][0]["InstanceId"]
        state = reservation["Instances"][0]["State"]
        security_groups = reservation["Instances"][0]["SecurityGroups"]

        # Terminate the private EC2 instance
        if int(state["Code"]) == 16 and security_groups[0]["GroupName"] == private_security_group:
            shieldx_logger.info("Terminate this EC2 instance - ID: {}".format(instance_id))
            shieldx_logger.info("Terminate this EC2 instance - State: {}".format(state))
            shieldx_logger.info("Terminate this EC2 Instance - Security Groups: {}".format(security_groups))
            ec2.terminate_ec2_instance(instance_id)
        else:
            shieldx_logger.warning("Skipping this EC2 instance - ID: {}".format(instance_id))
            shieldx_logger.warning("Skipping this EC2 instance - State: {}".format(state))
            shieldx_logger.warning("Skipping this EC2 instance - Security Groups: {}".format(security_groups))

# Helper routine
# Target, Key
# vpc, "CidrBlock"
# subnet, "CidrBlock"
# key pair, "KeyName"
# security group, "GroupName"
def get_target(target_key, target_value, list_of_targets):
    target_info = {
        "found": False,
        "target": None
    }

    for target in list_of_targets:
        if target[target_key] == target_value:
            target_info["target"] = target
            target_info["found"] = True
            break
        else:
            pass

    return target_info

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_vpc_deploy.py -v --setup-show -m aws_vpc
