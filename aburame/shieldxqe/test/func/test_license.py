import pytest
import time

# shieldx library
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

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
@pytest.mark.parametrize("license_json", [
        ("eval_unlimited.json"),
        ("devops_unlimited.json"),
        ("devops_single.json"),
        ("dev_unlimited.json"),
        ("dev_single.json"),
    ])
def test_bats_002_enable_license(sut_handle, license_json, shieldx_constants, datadir):
    manage = SysMgmt(sut_handle)
    config_reader = CCR()

    # Get license info
    resolved_input_json_file = str((datadir/license_json).resolve())
    license_info = dict(config_reader.read_json_config(resolved_input_json_file))

    license_key = license_info.get("key", None)
    license_type = license_info.get("type", None)
    license_capacity = license_info.get("capacity", None)

    # Set the license
    is_license_set = manage.set_license(license_key)

    # Allow passage to cleanup tables
    time.sleep(shieldx_constants["USER_WAIT"])

    # Check if license is set
    assert is_license_set == True, "Failed to activate license."

    # Get the license info
    license_info = manage.get_license(license_key)

    # Check expected to actual capacity
    fetched_capacity = license_info["expected_capacity"]
    assert license_capacity == fetched_capacity, "Capacity does not match."

    # Check expected to actual license type
    fetched_license_type = license_info["license_type"]
    assert license_type == fetched_license_type, "License type does not match."

    # Check if license is active
    fetched_license_state = license_info["current_state"]
    assert "active" == fetched_license_state, "License is not active."

@pytest.mark.system_info_bats
def test_bats_003_license_info(sut_handle, shieldx_logger):
    system_mgmt = SysMgmt(sut_handle)

    # Get the system info
    license_info = system_mgmt.get_license()

    shieldx_logger.info("License Info: {}".format(license_info))


# Sample run
#  python3 -m pytest shieldxqe/test/func/test_license.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m license_bats
