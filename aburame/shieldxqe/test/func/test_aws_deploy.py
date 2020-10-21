import pytest
import json
import time

# shieldx - sxapi library
from sxswagger.aws.vpc import VPC

@pytest.mark.aws_deploy
def test_ec2_operations(ec2_client, shieldx_constants, shieldx_logger):
    vpc = VPC(ec2_client=ec2_client)

    vpc_name = "Test-Juan-VPC"
    cidr_block  = "10.11.0.0/16"

    # Create VPC
    vpc_response = vpc.create_vpc(cidr_block)
    shieldx_logger.info("VPC Response: {}".format(vpc_response))

    # Fetch the VPC ID
    vpc_id = vpc_response["Vpc"]["VpcId"]
    shieldx_logger.info("VPC Name: {}".format(vpc_name))
    shieldx_logger.info("VPC ID: {}".format(vpc_id))

    # Create tag for VPC
    tag_response = vpc.create_tags(vpc_id, vpc_name)
    shieldx_logger.info("Tag Response: {}".format(tag_response))

    # Create Internet gateway
    igw_response = vpc.create_internet_gateway()
    shieldx_logger.info("Create IGW Response: {}".format(igw_response))
    igw_name = "Juan-IGW"
    igw_id = igw_response["InternetGateway"]["InternetGatewayId"]

    # Create tag for IGW
    tag_response = vpc.create_tags(igw_id, igw_name)
    shieldx_logger.info("Tag Response: {}".format(tag_response))

    # Attach the Internet gateway
    attach_response = vpc.attach_igw_to_vpc(igw_id, vpc_id)
    shieldx_logger.info("Attach Response: {}".format(attach_response))
