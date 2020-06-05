import pytest
import time

# shieldx library
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

@pytest.mark.system_info_bats
def test_staged_version(sut_handle, shieldx_logger):
    sys_mgmt = SysMgmt(sut_handle)

    # Get the staged version
    staged_version = sys_mgmt.get_staged_version()

    for item in staged_version:
        shieldx_logger.info("Staged Version: {}".format(item))

@pytest.mark.system_info_bats
def test_latest_version(sut_handle, shieldx_logger):
    sys_mgmt = SysMgmt(sut_handle)

    # Get the latest version
    latest_version = sys_mgmt.get_latest_version()

    for item in latest_version:
        shieldx_logger.info("Latest Version: {}".format(item))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_software_update.py -v --setup-show -s --um <umip> --username <user> --password <passwd> --collect-only
