import pytest

# shieldx library
from sxswagger.sxapi.cloud_management import CloudManagement as CloudMgmt

@pytest.mark.cloud_bats
def test_bats_000_create_infra(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # Create Infra Connector
    infra_id = cloud_mgmt.create_cloud_infra(
                   cloud_type="VMWARE",
                   username=None,
                   password=None,
               )

    # List Infra Connectors
    cloud_list = cloud_mgmt.get_cloud_infra()

    # Enumerate Infra Connectors
    for cloud_info in cloud_list:
        shieldx_logger.info("Cloud Type: {}".format(cloud_info["type"]))
        shieldx_logger.info("Cloud ID: {}".format(cloud_info["id"]))
        shieldx_logger.info("---")

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_cloud.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m cloud_bats
#  python3 -m pytest shieldxqe/test/func/test_cloud.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k create_infra
