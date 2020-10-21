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

@pytest.mark.content_bats
def test_bats_000_update_content(sut_handle, shieldx_constants, shieldx_logger):
    manage = SysMgmt(sut_handle)

    # Get the system info
    system_info = manage.get_system_info()

    shieldx_logger.info("Software: {}".format(system_info["version"]))
    shieldx_logger.info("Content: {}".format(system_info["contentVersion"]))

    # Initiate Content Update
    is_content_update_initiated = manage.update_content()

    # Allow compiler to finish task, needs to be dynamic
    time.sleep(shieldx_constants["USER_WAIT"])

    # Check if content update is initiated
    assert is_content_update_initiated == True, "Failed to initiate content update."

    # Allow compiler to finish task, needs to be dynamic
    time.sleep(shieldx_constants["USER_WAIT"])

    # Get the system info
    system_info = manage.get_system_info()

    shieldx_logger.info("Software: {}".format(system_info["version"]))
    shieldx_logger.info("Content: {}".format(system_info["contentVersion"]))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_content.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m content_bats

# Specific test run on a parameterized test
#  python3 -m pytest shieldxqe/test/func/test_content.py --collect-only
#  specific_test = test_bats_000_enable_license[0207ef1e-daac-547d-bcb1-82bf57607ab1-Devops-2Gbps]
#  python3 -m pytest shieldxqe/test/func/test_content.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k <specific_test>
