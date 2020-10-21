import pytest
import time

# shieldx library
from sxswagger.sxapi.cloud_management import CloudManagement as CloudMgmt

@pytest.mark.cloud_bats
def test_bats_000_check_cloud(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # List Infra Connectors
    cloud_list = cloud_mgmt.get_cloud_infra()

    # Enumerate Infra Connectors
    for cloud_info in cloud_list:
        shieldx_logger.info("Cloud Type: {}".format(cloud_info["type"]))
        shieldx_logger.info("Cloud ID: {}".format(cloud_info["id"]))
        shieldx_logger.info("Pseudo TAP: {}".format(cloud_info["inlinePassiveInspection"]))
        shieldx_logger.info("Cloud Info: {}".format(cloud_info))
        shieldx_logger.info("---")

@pytest.mark.cloud_bats
def test_bats_001_enable_pseudotap(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # List Infra Connectors
    cloud_list = cloud_mgmt.get_cloud_infra()

    name = "Juan-Azure-Cloud"
    pseudotap = True
    client_secret_key = "rwQBYeXhg5Isgyxlxa5cOW1wCdK7XdBE/vLYT4lA0I0="

    # Before change
    cloud = cloud_mgmt.get_cloud_infra_by_name(name)
    if cloud is not None:
        shieldx_logger.info("Before pseudotap change")
        shieldx_logger.info("Cloud Info: {}".format(cloud))
    else:
        assert False, "Get cloud failed!"

    # Set pseudotap
    cloud["inlinePassiveInspection"] = pseudotap
    cloud["clientSecretKey"] = client_secret_key
    updated_cloud = {key : value for key, value in cloud.items() if value}

    cloud_mgmt.update_cloud_infra(updated_cloud)

    # Check job
    time.sleep(60)

    # After change
    cloud = cloud_mgmt.get_cloud_infra_by_name(name)
    shieldx_logger.info("After pseudotap change")
    shieldx_logger.info("Cloud Info: {}".format(cloud))


@pytest.mark.cloud_bats
def test_bats_002_disable_pseudotap(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # List Infra Connectors
    cloud_list = cloud_mgmt.get_cloud_infra()

    name = "Juan-Azure-Cloud"
    pseudotap = False
    client_secret_key = "rwQBYeXhg5Isgyxlxa5cOW1wCdK7XdBE/vLYT4lA0I0="

    # Before change
    cloud = cloud_mgmt.get_cloud_infra_by_name(name)
    if cloud is not None:
        shieldx_logger.info("Before pseudotap change")
        shieldx_logger.info("Cloud Info: {}".format(cloud))
    else:
        assert False, "Get cloud failed!"

    # Set pseudotap
    cloud["inlinePassiveInspection"] = pseudotap
    cloud["clientSecretKey"] = client_secret_key
    update_cloud = {key : value for key, value in cloud.items() if value}

    shieldx_logger.info("Update Cloud: {}".format(update_cloud))
    cloud_mgmt.update_cloud_infra(update_cloud)

    # Check job
    time.sleep(60)

    # After change
    cloud = cloud_mgmt.get_cloud_infra_by_name(name)
    shieldx_logger.info("After pseudotap change")
    shieldx_logger.info("Cloud Info: {}".format(cloud))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_pseudo_tap.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m cloud_bats
