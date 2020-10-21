import pytest

# shieldx library
from sxswagger.sxapi.cloud_management import CloudManagement as CloudMgmt
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

@pytest.mark.cloud_bats
def test_bats_000_get_ip_pools(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # Infra ID
    infra_id = 1

    # Create resource Group
    ip_pools = cloud_mgmt.get_ip_pools(infra_id)

    for ip_pool in ip_pools:
        shieldx_logger.info("IP Pool: {}".format(ip_pool))

@pytest.mark.parametrize(
    "config_file", [
        "ip_pool1.json"
    ]
)
@pytest.mark.cloud_bats
def test_bats_001_create_ip_pool(
    sut_handle,
    datadir,
    config_file,
    shieldx_logger
):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # JSON Config Reader
    config_reader = CCR()

    # Selected Rule IDs
    resolved_input_json_file = str((datadir/config_file).resolve())
    ip_pool_config = config_reader.read_json_config(resolved_input_json_file)

    # Template
    ip_pool = ip_pool_config["ip_pool1"]

    # Cloud ID
    cloud_id = 1

    # IP Pool info
    ip_pool["cloudid"] = cloud_id
    ip_pool["name"] = "Juan-IP-Pool2"
    ip_pool["descr"] = "IP Pool for Backplane"
    ip_pool["gateway"] = "27.27.27.1"
    ip_pool["prefix"] = "24"
    ip_pool["dns"] = "172.16.10.14"
    ip_pool["domain"] = "shieldx.test"
    ip_pool["ranges"] = "27.27.27.11-27.27.27.20"


    # Create resource Group
    ip_pool_id = cloud_mgmt.create_ip_pool(ip_pool)

    shieldx_logger.info("IP Pool ID: {}".format(ip_pool_id))

@pytest.mark.cloud_bats
def test_bats_002_get_ip_pool_by_name(
    sut_handle,
    shieldx_logger
):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # Cloud ID
    cloud_id = 1

    # IP Pool
    ip_pool_name = "Juan-IP-Pool2"

    ip_pool = cloud_mgmt.get_ip_pool_by_name(cloud_id, ip_pool_name)

    shieldx_logger.info("IP Pool: {}".format(ip_pool))

@pytest.mark.cloud_bats
def test_bats_003_delete_ip_pool_by_name(
    sut_handle,
    shieldx_logger
):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # Cloud ID
    cloud_id = 1

    # IP Pool
    ip_pool_name = "Juan-IP-Pool2"

    is_deleted = cloud_mgmt.delete_ip_pool_by_name(cloud_id, ip_pool_name)

    shieldx_logger.info("IP Pool Deleted: {}".format(is_deleted))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_ip_pools.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m cloud_bats
