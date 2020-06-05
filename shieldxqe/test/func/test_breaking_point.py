import pytest
import time

# shieldx library
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

@pytest.mark.bp_bats
def test_bats_000_demo(ixia_handle, shieldx_constants, shieldx_logger):
    breaking_point = BreakingPoint(ixia_handle)
    bp_stats = RTS()

    # Get port status
    port_status = breaking_point.get_ports_status()
    shieldx_logger.info("Port Status: {}".format(port_status))

    # Reboot card, ports
    is_rebooted = False
    is_rebooted = breaking_point.reboot_card(shieldx_constants["IXIA_CARD"])
    shieldx_logger.info("Rebooting Chassis.")

    # Once rebooted, wait for chassis to be ready
    if is_rebooted:
        shieldx_logger.info("Wait while the chassis is booting ...")
        time.sleep(shieldx_constants["IXIA_WAIT"])

        # wait for 10 minutes or less
        for cycle in range(100):
            is_chassis_ready = breaking_point.check_chassis_config(shieldx_constants["IXIA_SLOT"])

            shieldx_logger.info("Chassis is ready: {}".format(is_chassis_ready))
            if is_chassis_ready:
                break
            else:
                # Wait
                shieldx_logger.info("Wait until the chassis is ready ...")
                time.sleep(shieldx_constants["IXIA_WAIT"])
        else:
            shieldx_logger.info("Wait exceeded.")
    else:
        pass

    shieldx_logger.info("Ready to reserve ports.")

    ports_reserved = breaking_point.reserve_ports(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"])

    if ports_reserved:
        shieldx_logger.info("Ports are now reserved.")

        # Model name, this is what BP calls the test name
        model_name = "SxSecurityTest_BATS"
        #model_name = "SxSecurityTest_NoSSL_C2S_2010"

        test_start = breaking_point.start_test(model_name)

        if test_start:
            test_id = breaking_point.get_test_id()

            rts = breaking_point.get_real_time_stats(test_id)
            shieldx_logger.info("RTS: {}".format(rts))
            progress = rts["progress"]

            # Monitor progress and proceed after test is 100.0% completed
            while float(progress) < shieldx_constants["IXIA_TEST_COMPLETE"]:
                # Wait before the next progress check
                time.sleep(5 * shieldx_constants["IXIA_WAIT"])

                # Get RTS based on test ID
                rts = breaking_point.get_real_time_stats(test_id)

                # Extract progress
                progress = rts["progress"]

            # Parse values
            summary_stats = bp_stats.parse_stats(rts["rts"])

            shieldx_logger.info("Total Strikes: {}".format(summary_stats["totalStrikes"]))
            shieldx_logger.info("Total Allowed: {}".format(summary_stats["totalAllowed"]))
            shieldx_logger.info("Total Blocked: {}".format(summary_stats["totalBlocked"]))
        else:
            shieldx_logger.info("Test failed to start.")
            

        ports_freed = breaking_point.unreserve_ports(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"])

        if ports_freed:
            shieldx_logger.info("Ports are now unreserved.")
        else:
            pass
    else:
        pass

    assert True

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_breaking_point.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m bp_bats
#  python3 -m pytest shieldxqe/test/func/test_breaking_point.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k demo
