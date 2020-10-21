import pytest
import time

# shieldx library
from sxswagger.vmware.infrastructure import Infrastructure as VmwareInfra
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

@pytest.mark.vmware_bats
@pytest.mark.parametrize("vmware_cred", [
        ("qe_vcenter.json"),
        ("test_vcenter.json"),
    ])
def test_check_info(
    vmware_cred,
    datadir,
    shieldx_logger
):
    config_reader = CCR()

    # Get VMware Credentials
    resolved_input_json_file = str((datadir/vmware_cred).resolve())
    vmware_credentials = dict(config_reader.read_json_config(resolved_input_json_file))

    vcenter_ip = vmware_credentials.get("vcenter_ip", None)
    username = vmware_credentials.get("username", None)
    password = vmware_credentials.get("password", None)

    # Connect
    infra_client = VmwareInfra()
    infra_client.connect(vcenter_ip, username, password)

    system_info = infra_client.get_system_info()

    shieldx_logger.info("Name: {}".format(system_info["name"]))
    shieldx_logger.info("Version: {}".format(system_info["version"]))

    # Disconnect
    infra_client.disconnect()

@pytest.mark.vmware_bats
@pytest.mark.parametrize("vmware_cred", [
        ("qe_vcenter.json"),
        ("test_vcenter.json"),
    ])
def test_check_networks(
    vmware_cred,
    datadir,
    shieldx_logger
):
    config_reader = CCR()

    # Get VMware Credentials
    resolved_input_json_file = str((datadir/vmware_cred).resolve())
    vmware_credentials = dict(config_reader.read_json_config(resolved_input_json_file))

    vcenter_ip = vmware_credentials.get("vcenter_ip", None)
    username = vmware_credentials.get("username", None)
    password = vmware_credentials.get("password", None)

    # Connect
    infra_client = VmwareInfra()
    infra_client.connect(vcenter_ip, username, password)

    # All Networks
    all_networks = infra_client.get_all_networks()
    for network in all_networks:
        shieldx_logger.info("Network: {}".format(network.name))

    # Disconnect
    infra_client.disconnect()

@pytest.mark.vmware_bats
@pytest.mark.parametrize("vmware_cred", [
        ("qe_vcenter.json"),
        ("test_vcenter.json"),
    ])
def test_check_resources(
    vmware_cred,
    datadir,
    shieldx_logger
):
    config_reader = CCR()

    # Get VMware Credentials
    resolved_input_json_file = str((datadir/vmware_cred).resolve())
    vmware_credentials = dict(config_reader.read_json_config(resolved_input_json_file))

    vcenter_ip = vmware_credentials.get("vcenter_ip", None)
    username = vmware_credentials.get("username", None)
    password = vmware_credentials.get("password", None)

    # Connect
    infra_client = VmwareInfra()
    infra_client.connect(vcenter_ip, username, password)

    # All Virtual Machines
    all_vms = infra_client.get_all_vm()
    for vm in all_vms:
       shieldx_logger.info("Vitual machine: {}".format(vm.name))

    # All Datacenters
    all_dcs = infra_client.get_all_dc()
    for dc in all_dcs:
        shieldx_logger.info("Datacenter: {}".format(dc.name))

    # All Datastores
    all_dss = infra_client.get_all_ds()
    for ds in all_dss:
        shieldx_logger.info("Datastore: {}".format(ds.name))

    # All Clusters
    all_clusters = infra_client.get_all_clusters()
    for cluster in all_clusters:
        shieldx_logger.info("Cluster: {}".format(cluster.name))

    # All Hosts
    all_hosts = infra_client.get_all_hs()
    for host in all_hosts:
        shieldx_logger.info("Host: {}".format(host.name))

    # All Networks
    all_networks = infra_client.get_all_networks()
    for network in all_networks:
        shieldx_logger.info("Network: {}".format(network.name))

    # Disconnect
    infra_client.disconnect()

@pytest.mark.vmware_bats
@pytest.mark.parametrize("vmware_cred", [
        ("qe_vcenter.json"),
    ])
def test_create_vswitch(
    vmware_cred,
    datadir,
    shieldx_logger
):
    config_reader = CCR()

    # Get VMware Credentials
    resolved_input_json_file = str((datadir/vmware_cred).resolve())
    vmware_credentials = dict(config_reader.read_json_config(resolved_input_json_file))

    vcenter_ip = vmware_credentials.get("vcenter_ip", None)
    username = vmware_credentials.get("username", None)
    password = vmware_credentials.get("password", None)
    esx_host = vmware_credentials.get("esx_host", None)

    # Connect
    infra_client = VmwareInfra()
    infra_client.connect(vcenter_ip, username, password)

    # All Hosts
    all_hosts = infra_client.get_all_hs()
    for host in all_hosts:
        if host.name == esx_host:
            shieldx_logger.info("Host: {}".format(host.name))
            break
        else:
            pass

    # vSwitch config
    vswitch_config = {
        "name": "Juan-TestCreate-vSwitch",
        "num_ports": 120,
        "mtu": 1500
    }

    # Create Standard vSwitch
    infra_client.add_vswitch_to_host(host, vswitch_config)

    # Add verification

    # Disconnect
    infra_client.disconnect()

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_vmware_infra.py -v --setup-show -s --collect-only
