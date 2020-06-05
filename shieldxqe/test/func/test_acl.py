import pytest

# shieldx - policy management
from sxswagger.sxapi.policy_management import AccessControl as ACL_Mgmt
from sxswagger.sxapi.policy_management import SecurityPolicySets as SPS_Mgmt
from sxswagger.sxapi.policy_management import ThreatPrevention as TPP_Mgmt

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - ixia management
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

@pytest.mark.explore_breaking_point
@pytest.mark.parametrize("traffic_profile",
    [
        "SxDevOnly_StrikesTest1",
    ]
)
def test_explore_strikes_stats(sut_handle, ixia_handle, traffic_profile, shieldx_constants, shieldx_logger):
    # Initialize
    # Traffic - Breaking Point handle
    breaking_point = BreakingPoint(ixia_handle)

    # Send traffic
    summary_stats = breaking_point.send_strikes_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)
    shieldx_logger.info("Summary Stats: {}".format(summary_stats))

@pytest.mark.explore_breaking_point
@pytest.mark.parametrize("traffic_profile",
    [
        "SxDevOnly_TputTest1",
    ]
)
def test_explore_perf_stats(sut_handle, ixia_handle, traffic_profile, shieldx_constants, shieldx_logger):
    # Initialize
    # Traffic - Breaking Point handle
    breaking_point = BreakingPoint(ixia_handle)

    # Send traffic
    processed_stats = breaking_point.send_perf_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)
    shieldx_logger.info("Processed Stats: {}".format(processed_stats))

@pytest.mark.perf_testing
@pytest.mark.parametrize(
    "policy_name, traffic_profile", [
        # Policy Name, BP Traffic Profile
        ("Discover", "SxDevOnly_TputTest1"),
    ]
)
def test_perf_throughput(sut_handle, ixia_handle,
        shieldx_constants, shieldx_logger,
        policy_name, traffic_profile):
    # Initialize
    # DUT
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)
    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    # SPS
    sps = sps_mgmt.get_sps_by_name(policy_name)
    sps_name = sps["name"]
    sps_id = sps["id"]

    # Assign SPS to ACL
    acl_policy = acl_mgmt.get_acl_by_name("Default ACL Policy")
    acl_policy["spsId"] = sps_id

    is_updated = acl_mgmt.update_acl(acl_policy)

    # Wait for the Policy to be updated
    time.sleep(5 * shieldx_constants["USER_WAIT"])

    # Get the system info
    system_info = sys_mgmt.get_system_info()
    software_version = system_info["version"]
    content_version = system_info["contentVersion"]

    # Send traffic
    processed_stats = breaking_point.send_perf_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

    # Results
    shieldx_logger.info("Software: {}".format(software_version))
    shieldx_logger.info("Content: {}".format(content_version))
    shieldx_logger.info("Processed Stats: {}".format(processed_stats))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_perf.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
