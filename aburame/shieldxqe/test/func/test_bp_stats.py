import pytest

# shieldx - ixia library
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

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_bp_stats.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
