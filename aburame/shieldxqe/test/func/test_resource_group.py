import pytest

# shieldx library
from sxswagger.sxapi.cloud_management import CloudManagement as CloudMgmt
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

@pytest.mark.cloud_bats
def test_bats_000_get_resource_groups(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # Create resource Group
    resource_groups = cloud_mgmt.get_resource_groups()

    for resource_group in resource_groups:
        shieldx_logger.info("Resource Group: {}".format(resource_group))

@pytest.mark.parametrize(
    "config_file", [
        "rg1.json"
    ]
)
@pytest.mark.cloud_bats
def test_bats_001_create_resource_group(sut_handle, config_file, datadir, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # JSON Config Reader
    config_reader = CCR()

    # Selected Rule IDs
    resolved_input_json_file = str((datadir/config_file).resolve())
    rg_config = config_reader.read_json_config(resolved_input_json_file)

    # Create resource Group
    resource_group = rg_config["rg1"]
    resource_group["name"] = "VP_ResourceGroup"
    resource_group["description"] = "CIDR Based RG"
    resource_group["purpose"] = "POLICY"
    resource_group["resourceType"] = "CIDR"
    resource_group["memberList"] = [
        {"id": 0, "cidr": "192.168.131.5/32"},
        {"id": 0, "cidr": "192.168.131.51/32"}
    ]

    rg_id = cloud_mgmt.create_resource_group(resource_group)

    shieldx_logger.info("Resource Group Created, ID: {}".format(rg_id))

@pytest.mark.cloud_bats
def test_bats_002_get_resource_group_by_name(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # Create resource Group
    rg_name = "VP_ResourceGroup"

    rg = cloud_mgmt.get_resource_group_by_name(rg_name)

    shieldx_logger.info("Resource Group: {}".format(rg))

@pytest.mark.cloud_bats
def test_bats_003_del_resource_group_by_name(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # Create resource Group
    rg_name = "VP_ResourceGroup"

    is_deleted = cloud_mgmt.remove_resource_group_by_name(rg_name)

    shieldx_logger.info("Remove RG Status: {}".format(is_deleted))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_resource_group.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m cloud_bats
