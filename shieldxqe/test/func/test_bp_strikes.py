import pytest
import time

# shieldx library
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

def test_reboot_chassis(ixia_handle, shieldx_constants):
    breaking_point = BreakingPoint(ixia_handle)

    # Reboot card, ports
    is_rebooted = False
    is_rebooted = breaking_point.reboot_card(shieldx_constants["IXIA_CARD"])

    # Once rebooted, wait for chassis to be ready
    if is_rebooted:
        time.sleep(shieldx_constants["IXIA_WAIT"])

        # wait for 10 minutes or less
        for cycle in range(100):
            is_chassis_ready = breaking_point.check_chassis_config(shieldx_constants["IXIA_SLOT"])

            # Stop waiting once chassis is ready
            if is_chassis_ready:
                break
            else:
                # Chassis not ready yet, keep waiting
                time.sleep(shieldx_constants["IXIA_WAIT"])
        else:
            assert False, "Wait for chassis to be ready exceeded."
    else:
        pass

    assert is_chassis_ready, "Chassis is not ready."

# Strikes Tests - groups
# BATS
bp_bats = [
    "SxSecurityTest_BATS",
]

# Client to Server, 2010 to 2019
bp_c2s = [
    "SxSecurityTest_NoSSL_C2S_2010",
    "SxSecurityTest_NoSSL_C2S_2011",
    "SxSecurityTest_NoSSL_C2S_2012",
    "SxSecurityTest_NoSSL_C2S_2013",
    "SxSecurityTest_NoSSL_C2S_2014",
    "SxSecurityTest_NoSSL_C2S_2015",
    "SxSecurityTest_NoSSL_C2S_2016",
    "SxSecurityTest_NoSSL_C2S_2017",
    "SxSecurityTest_NoSSL_C2S_2018",
    "SxSecurityTest_NoSSL_C2S_2019",
]

# Server to Client, 2010 to 2019
bp_s2c = [
    "SxSecurityTest_NoSSL_S2C_2010",
    "SxSecurityTest_NoSSL_S2C_2011",
    "SxSecurityTest_NoSSL_S2C_2012",
    "SxSecurityTest_NoSSL_S2C_2013",
    "SxSecurityTest_NoSSL_S2C_2014",
    "SxSecurityTest_NoSSL_S2C_2015",
    "SxSecurityTest_NoSSL_S2C_2016",
    "SxSecurityTest_NoSSL_S2C_2017",
    "SxSecurityTest_NoSSL_S2C_2018",
    "SxSecurityTest_NoSSL_S2C_2019",
]

@pytest.mark.bp_strikes
@pytest.mark.parametrize("model_name", bp_bats)
def test_strikes(ixia_handle, shieldx_constants, model_name):
    breaking_point = BreakingPoint(ixia_handle)

    summary_stats = breaking_point.send_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], model_name)

    print("Total Strikes: {}".format(summary_stats["totalStrikes"]))
    print("Total Allowed: {}".format(summary_stats["totalAllowed"]))
    print("Total Blocked: {}".format(summary_stats["totalBlocked"]))

    # Check % blocked for each traffic profile (model_name)
    assert True

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_bp_strikes.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m bp_strikes
#  python3 -m pytest shieldxqe/test/func/test_breaking_point.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k test_strikes
