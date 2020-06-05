import pytest
import time

# shieldx library
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

@pytest.mark.system_info_bats
def test_bats_000_system_info(sut_handle, shieldx_logger):
    manage = SysMgmt(sut_handle)

    # Get the system info
    system_info = manage.get_system_info()

    shieldx_logger.info("Mgmt Major Version: {}".format(system_info["majorVersion"]))
    shieldx_logger.info("Mgmt Minor Version: {}".format(system_info["minorVersion"]))
    shieldx_logger.info("Mgmt Build Number: {}".format(system_info["buildNumber"]))
    shieldx_logger.info("Software: {}".format(system_info["version"]))
    shieldx_logger.info("Content: {}".format(system_info["contentVersion"]))
    shieldx_logger.info("Uptime: {}".format(system_info["systemUptime"]))
    shieldx_logger.info("Timezone: {}".format(system_info["timezone"]))

    software_version = ".".join((system_info["majorVersion"], system_info["minorVersion"], system_info["buildNumber"]))

    assert software_version in system_info["version"], "Issue in software version."

@pytest.mark.license_bats
@pytest.mark.parametrize("license, license_type, capacity",
                         [("41b74f0e-bc6f-510d-8182-9521effb8fe8", "Devops", "unlimited"),
                          ("46c1e2eb-81d8-57c6-af46-0f19798d1938", "Dev", "unlimited"),
                          ("6f598f03-4b3b-5002-bca0-abf05d79009f", "Eval", "unlimited"),
                          ("4dfbe3d0-9494-5408-bb51-c172c8b0695f", "Dev", "2Gbps"),
                          ("0207ef1e-daac-547d-bcb1-82bf57607ab1", "Devops", "2Gbps"),
                         ])
def test_bats_002_enable_license(sut_handle, shieldx_constants, license, license_type, capacity):
    manage = SysMgmt(sut_handle)

    # Set the license
    is_license_set = manage.set_license(license)

    # Allow passage to cleanup tables
    time.sleep(shieldx_constants["USER_WAIT"])

    # Check if license is set
    assert is_license_set == True, "Failed to activate license."

    # Get the license info
    license_info = manage.get_license(license)

    # Check expected to actual capacity
    fetched_capacity = license_info["expected_capacity"]
    assert capacity in fetched_capacity, "Capacity does not match."

    # Check expected to actual license type
    fetched_license_type = license_info["license_type"]
    assert license_type in fetched_license_type, "License type does not match."

    # Check if license is active
    fetched_license_state = license_info["current_state"]
    assert "active" in fetched_license_state, "License is not active."

@pytest.mark.system_info_bats
def test_bats_003_license_info(sut_handle, shieldx_logger):
    system_mgmt = SysMgmt(sut_handle)

    # Get the system info
    license_info = system_mgmt.get_license()

    shieldx_logger.info("License Info: {}".format(license_info))


# Sample run
#  python3 -m pytest shieldxqe/test/func/test_license.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m license_bats
