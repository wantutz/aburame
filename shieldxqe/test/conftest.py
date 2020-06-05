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

# Test Common Config

# standard library
import pytest

# 3rd party library
import boto3

# shieldx library
from sxswagger.sxapi.rest_session import RestSession as SxSession
from sxswagger.ixia.rest_session import RestSession as IxiaSession
from sxswagger.common.custom_logger import CustomLogger

@pytest.fixture(scope="session")
def shieldx_logger():
    """ Singleton logger """

    return CustomLogger().get_logger()

@pytest.fixture(scope="session")
def shieldx_constants():
    """ Constants that are used by tests. """

    return {
        # A minute a pop
        "USER_WAIT": 60,

        # IXIA Constants
        #"IXIA_IP": "172.16.254.10",
        "IXIA_IP": "ps10g-p0860284.shieldxdev.local",
        "IXIA_USER": "admin",
        "IXIA_PASS": "admin",
        "IXIA_CARD": "1",
        "IXIA_SLOT": "1",
        "IXIA_PORTS": [0, 1],
        "IXIA_WAIT": 10,

        "IXIA_TEST_COMPLETE": 100.0,

        # IP Blacklist
        "SX_BL_ALERT_ONLY": 1,
        "SX_BL_BLOCK_AND_ALERT": 2,

        # Reporting
        "SX_REPORT_REPO": "/var/www/html/",
        "SX_BUCKET_REPO": "BpBucketTest/",
        "SX_CPS_REPO": "BpCpsTest/",
        "SX_PERF_REPO": "BpPerfTest/",
        "SX_STRIKES_REPO": "BpStrikesTest/",
        "SX_ABURAME_REPO": "AburameTest/",
        "SX_TPP_RULES_REPO": "SxTppRulesCount/",
    }

@pytest.fixture(scope="session")
def sut_handle(pytestconfig):
    # Initialize REST Session
    sx_session = SxSession(ip=pytestconfig.option.um,
                     username=pytestconfig.option.username,
                     password=pytestconfig.option.password
                 )

    # Setup - Login to UM
    sx_session.login()

    yield sx_session

    # Teardown - Logout from UM
    sx_session.logout()

@pytest.fixture(scope="function")
def ixia_handle(shieldx_constants):
    # Initialize REST Session
    ixia_session = IxiaSession(
                       ip=shieldx_constants["IXIA_IP"],
                       username=shieldx_constants["IXIA_USER"],
                       password=shieldx_constants["IXIA_PASS"]
                   )

    # Setup - Login to Ixia
    ixia_session.login()

    yield ixia_session

    # Teardown - Logout from Ixia
    ixia_session.logout()

@pytest.fixture(scope="session")
def ec2_client():
    ec2_client = boto3.client("ec2")

    yield ec2_client

@pytest.fixture(scope="session")
def s3_client():
    s3_client = boto3.client("s3")

    yield s3_client

@pytest.fixture(scope="session")
def s3_resource():
    s3_resource = boto3.resource("s3")

    yield s3_resource

def pytest_addoption(parser):
    """ Fetch config from command line. """

    parser.addoption("--shieldx", action="store_true",
                     help="ShieldX Flag")
    parser.addoption("--branch", action="store", default="SxRel2.1",
                     help="Branch: Master | SxRel2.0 | SxRel2.1")
    parser.addoption("--um", action="store", help="ShieldX UM")
    parser.addoption("--username", action="store", help="ShieldX REST Username")
    parser.addoption("--password", action="store", help="ShieldX REST Password")
    parser.addoption("--license", action="store", help="ShieldX License")
    parser.addoption("--malware_key", action="store", help="API Key for Malware Cloud")
    parser.addoption(
        "--stringinput",
        action="append",
        default=[],
        help="list of stringinputs to pass to test functions",
    )

def pytest_generate_tests(metafunc):
    if "stringinput" in metafunc.fixturenames:
        metafunc.parametrize("stringinput", metafunc.config.getoption("stringinput"))

