import pytest
import time

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - policy management
from sxswagger.sxapi.policy_management import AccessControl as ACL_Mgmt
from sxswagger.sxapi.policy_management import SecurityPolicySets as SPS_Mgmt
from sxswagger.sxapi.policy_management import ThreatPrevention as TPP_Mgmt

# shieldx - blacklist/whitelist management
from sxswagger.sxapi.blacklist import Blacklist
from sxswagger.sxapi.whitelist import Whitelist

# shieldx - common
from sxswagger.common.custom_results import CustomResults as Result_Mgmt

# shieldx - ixia library
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

@pytest.mark.blacklist_bats
def test_bats_000_disable_blacklist(sut_handle, shieldx_constants):
    blacklist = Blacklist(sut_handle)
    is_disabled = blacklist.disable_ip_blacklist()

    # Allow passage to cleanup tables
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_disabled == True, "IP Blacklist is disabled successfully."

@pytest.mark.blacklist_bats
def test_bats_001_blacklist_is_disabled(sut_handle):
    blacklist = Blacklist(sut_handle)
    status = blacklist.get_ip_blacklist()

    assert status == [], "IP Blacklist is not disabled."

@pytest.mark.blacklist_bats
@pytest.mark.parametrize("import_file",
                         ["blacklist_bats_subnet1.txt",
                          "blacklist_bats_subnet2.txt",
                          "blacklist_bats_subnet3.txt",
                        ])
def test_bats_002_import_by_file(sut_handle, datadir, import_file, shieldx_constants):
    # Get the full path and convert it to string
    file_name = str((datadir/import_file).resolve())

    blacklist = Blacklist(sut_handle)
    is_imported = blacklist.import_listed_ip(file_name)

    # Allow passage to import the file and commit the config change
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_imported == True, "Import by file failed."

@pytest.mark.blacklist_bats
@pytest.mark.parametrize("import_feed",
                         ["https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bambenek_c2.ipset",
                          "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bi_any_2_1d.ipset",
                          "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/voipbl.netset",
                          "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_180d.ipset",
                        ])
def test_bats_003_import_by_feed(sut_handle, import_feed, shieldx_constants):
    blacklist = Blacklist(sut_handle)
    is_imported = blacklist.import_listed_feed(import_feed)

    # Allow passage to import the file and commit the config change
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_imported == True, "Import by URL feed failed."

@pytest.mark.blacklist_bats
@pytest.mark.parametrize("response_action", [2, 1, 1, 2, 1])
def test_bats_004_change_response_action(sut_handle, response_action, shieldx_constants):
    blacklist = Blacklist(sut_handle)
    is_action_set = blacklist.set_ip_blacklist_action(response_action)

    # Allow passage to change response action
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_action_set == True, "Change response action failed."

    # Check that action is set successfully before verifying settings
    if is_action_set:
        ip_blacklist_global_settings = blacklist.get_ip_blacklist_global_settings()

        if "action" in ip_blacklist_global_settings:
            response_action_from_config = ip_blacklist_global_settings["action"]

            assert int(response_action_from_config) == int(response_action), "Response action does not match."
        else:
            assert False, "Global settings action not found."
    else:
        assert False, "Issue with setting response action"

@pytest.mark.blacklist_bats
@pytest.mark.parametrize("export_file",
                         ["blacklist_bats_export_attempt1.txt",
                          "blacklist_bats_export_attempt2.txt",
                          "blacklist_bats_export_attempt3.txt",
                        ])
def test_bats_005_export_blacklist(sut_handle, datadir, export_file, shieldx_constants, shieldx_logger):
    # Get the full path and convert it to string
    file_name = str(datadir/export_file)

    shieldx_logger.info("Export file: {}".format(file_name))

    blacklist = Blacklist(sut_handle)
    is_exported = blacklist.export_listed_ip(file_name)

    # Allow passage to export the blacklist config to a file
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_exported == True, "Export config file failed."

@pytest.mark.blacklist_bats
def test_bats_006_whitelist_is_disabled(sut_handle, shieldx_constants):
    whitelist = Whitelist(sut_handle)
    whitelist_info = whitelist.get_ip_whitelist()

    # Allow passage to export the blacklist config to a file
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert int(whitelist_info["ipv4"]) == 0, "IPv4 whitelist is not empty"
    assert int(whitelist_info["ipv6"]) == 0, "IPv6 whitelist is not empty"
    assert int(whitelist_info["cidr"]) == 0, "CIDR whitelist is not empty"
    assert int(whitelist_info["sumtotal"]) == 0, "Any of the whitelist is not empty"

@pytest.mark.blacklist_bats
@pytest.mark.parametrize("iplist",
                         ["1.1.0.0/16",
                          "172.16.27.0/24",
                          "200.2.2.0/24",
                        ])
def test_bats_007_import_whitelist(sut_handle, datadir, iplist, shieldx_constants):
    whitelist = Whitelist(sut_handle)
    is_imported = whitelist.import_listed_ip(iplist, "1")

    # Allow passage to import whitelist
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_imported == True, "Import whitelist failed."


@pytest.mark.blacklist_bats
@pytest.mark.parametrize("export_file",
                         ["whitelist_bats_export_attempt1.txt",
                          "whitelist_bats_export_attempt2.txt",
                          "whitelist_bats_export_attempt3.txt",
                        ])
def test_bats_008_export_whitelist(sut_handle, datadir, export_file, shieldx_constants, shieldx_logger):
    # Get the full path and convert it to string
    file_name = str(datadir/export_file)

    whitelist = Whitelist(sut_handle)
    is_exported = whitelist.export_listed_ip(file_name)
    shieldx_logger.info("Export file: {}".format(file_name))

    # Allow passage to export the blacklist config to a file
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_exported == True, "Export config file failed."

@pytest.mark.blacklist_bats
@pytest.mark.parametrize("import_file",
                         ["empty_file.txt",
                        ])
def test_bats_009_import_empty_file(sut_handle, datadir, import_file, shieldx_constants):
    # Get the full path and convert it to string
    file_name = str((datadir/import_file).resolve())

    blacklist = Blacklist(sut_handle)
    is_imported = blacklist.import_listed_ip(file_name)

    # Allow passage to import the file and commit the config change
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_imported == False, "Import empty file is allowed."

@pytest.mark.blacklist_aws
@pytest.mark.parametrize("import_file",
                         ["aws_client.txt",
                        ])
def test_bats_010_aws_import_client(sut_handle, datadir, import_file, shieldx_constants):
    # Get the full path and convert it to string
    file_name = str((datadir/import_file).resolve())

    blacklist = Blacklist(sut_handle)
    is_imported = blacklist.import_listed_ip(file_name)

    # Allow passage to import the file and commit the config change
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_imported == True, "AWS - Import by file failed."

@pytest.mark.blacklist_aws
@pytest.mark.parametrize("import_file",
                         ["aws_xff.txt",
                        ])
def test_bats_011_aws_import_xff(sut_handle, datadir, import_file, shieldx_constants):
    # Get the full path and convert it to string
    file_name = str((datadir/import_file).resolve())

    blacklist = Blacklist(sut_handle)
    is_imported = blacklist.import_listed_ip(file_name)

    # Allow passage to import the file and commit the config change
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_imported == True, "AWS - Import by file failed."

@pytest.mark.blacklist_aws
def test_bats_012_change_response_action_to_alert(sut_handle, shieldx_constants):
    blacklist = Blacklist(sut_handle)
    response_action = shieldx_constants["SX_BL_ALERT_ONLY"]
    is_action_set = blacklist.set_ip_blacklist_action(response_action)

    # Allow passage to change response action
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_action_set == True, "Change response action failed."

    # Check that action is set successfully before verifying settings
    if is_action_set:
        ip_blacklist_global_settings = blacklist.get_ip_blacklist_global_settings()

        if "action" in ip_blacklist_global_settings:
            response_action_from_config = ip_blacklist_global_settings["action"]

            assert int(response_action_from_config) == int(response_action), "Response action does not match."
        else:
            assert False, "Global settings action not found."
    else:
        assert False, "Issue with setting response action"

@pytest.mark.blacklist_aws
def test_bats_012_change_response_action_to_block(sut_handle, shieldx_constants):
    blacklist = Blacklist(sut_handle)
    response_action = shieldx_constants["SX_BL_BLOCK_AND_ALERT"]
    is_action_set = blacklist.set_ip_blacklist_action(response_action)

    # Allow passage to change response action
    time.sleep(2 * shieldx_constants["USER_WAIT"])

    assert is_action_set == True, "Change response action failed."

    # Check that action is set successfully before verifying settings
    if is_action_set:
        ip_blacklist_global_settings = blacklist.get_ip_blacklist_global_settings()

        if "action" in ip_blacklist_global_settings:
            response_action_from_config = ip_blacklist_global_settings["action"]

            assert int(response_action_from_config) == int(response_action), "Response action does not match."
        else:
            assert False, "Global settings action not found."
    else:
        assert False, "Issue with setting response action"

@pytest.mark.blacklist_func
def test_func_init_setup(sut_handle, shieldx_constants, shieldx_logger):
    """
        1. Use canned SPS (e.g. Discover) so there's no blocking other than blacklist.
    """
    shieldx_logger.info("Use canned SPS (e.g. Discover) so there's no blocking other than blacklist.")

    # DUT
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)

    #### Blacklist, test with SPS = Discover
    policy_name = "Discover"
    sps = sps_mgmt.get_sps_by_name(policy_name)

    is_updated = False
    default_acl = "Default ACL Policy"
    acl_policy = acl_mgmt.get_acl_by_name(default_acl)

    if acl_policy is not None:
        # Modify the ACL Rule in the Default ACL Policy
        acl_policy["spsId"] = sps["id"]
        acl_policy["aclRules"][0]["spsId"] = sps["id"]

        # Update the ACL
        shieldx_logger.info("Update ACL: {}".format(acl_policy))
        is_updated = acl_mgmt.update_acl(acl_policy)

        assert is_updated == True, "Unable to update ACL."
    else:
        assert False, "Not able to find ACL."

@pytest.mark.blacklist_func
@pytest.mark.parametrize("import_file, traffic_profile",
                         [("blacklist_network_neighborhood_1.txt", "SxSecurityTest_Blacklist1"),
                        ])
def test_func_block_traffic(sut_handle, datadir, import_file, ixia_handle, traffic_profile, shieldx_constants, shieldx_logger):
    """
    Suite 1
        1. Start with IP Blacklist disabled
        2. Send Traffic - Expect to go through
        3. Enable and Import blacklist from a file
        4. Send Traffic  - Expect to be blocked
        5. Check Settings: Response Action (default - Block and Alert)
        6. Check Settings: Imported File
        7. Change Response Action from "Block and Alert" to "Alert Only"
        8. Check Settings: Response Action (Alert Only)
        9. Send Traffic - Expect to go through
       10. Disable IP Blacklist
    """
    # Initialize
    # DUT
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)

    # Initialize
    # Blacklist
    blacklist = Blacklist(sut_handle)
    # Traffic - Breaking Point handle
    breaking_point = BreakingPoint(ixia_handle)

    # Get the system info
    system_info = sys_mgmt.get_system_info()
    software_version = system_info["version"]
    content_version = system_info["contentVersion"]
    # Get the license info
    license_info = sys_mgmt.get_license()
    # Get SPS in default ACL
    default_acl = "Default ACL Policy"
    acl_policy = acl_mgmt.get_acl_by_name(default_acl)
    sps_id = acl_policy["aclRules"][0]["spsId"]
    sps = sps_mgmt.get_sps_by_id(sps_id)

    if sps is not None:
        sps_name = sps["name"]
    else:
        sps_name = "None"

    # Reporting
    result_dir = "{}{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_ABURAME_REPO"], "IP_Blacklist/")
    column_names = ["Build", "SPS", "Test Name", "Result"]
    column_widths = [26, 16, 80, 10]
    shieldx_results = Result_Mgmt(result_dir, column_names, column_widths)

    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Start with IP Blacklist disabled.
    test_name = "Is IP Blacklist disabled?"
    shieldx_logger.info(test_name)
    is_disabled = blacklist.disable_ip_blacklist()
    time.sleep(2 * shieldx_constants["USER_WAIT"])
    status = "PASSED" if is_disabled else "FAILED"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Get IP Blacklist Global settings
    test_name = "Get IP Blacklist global settings - DISABLED."
    shieldx_logger.info(test_name)
    global_settings = blacklist.get_ip_blacklist_global_settings()
    shieldx_logger.info("IP Blacklist Global Setttings: {}".format(global_settings))
    status = "QTAD-5378"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Send traffic and expect the traffic go through (Blacklist Disabled).
    test_name = "Send traffic and expect the traffic go through (Blacklist Disabled)."
    shieldx_logger.info(test_name)
    stats = breaking_point.send_strikes_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)
    status = "PASSED" if int(stats["total_blocked"]) == 0 else "FAILED"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Enable IP Blacklist, import from file.
    test_name = "Enable IP Blacklist, import from file."
    shieldx_logger.info(test_name)
    # Get the full path and convert it to string
    file_name = str((datadir/import_file).resolve())
    # Import Blacklist - IP Set
    is_imported = blacklist.import_listed_ip(file_name)
    time.sleep(2 * shieldx_constants["USER_WAIT"])
    status = "PASSED" if is_imported else "FAILED"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Get IP Blacklist Global settings
    test_name = "Get IP Blacklist global settings - ENABLED."
    shieldx_logger.info(test_name)
    global_settings = blacklist.get_ip_blacklist_global_settings()
    shieldx_logger.info("IP Blacklist Global Setttings: {}".format(global_settings))
    status = "QTAD-5378"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Send traffic and expect the traffic blocked (DENY-Blacklist).
    test_name = "Send traffic and expect the traffic blocked (DENY-Blacklist)."
    shieldx_logger.info(test_name)
    stats = breaking_point.send_strikes_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)
    status = "PASSED" if int(stats["total_allowed"]) == 0 else "FAILED"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Change Response Action from 'Block and Alert(default)' to 'Alert Only'.
    test_name = "Change Response Action from 'Block and Alert(default)' to 'Alert Only'."
    shieldx_logger.info(test_name)
    is_action_set = blacklist.set_ip_blacklist_action(shieldx_constants["SX_BL_ALERT_ONLY"])
    time.sleep(2 * shieldx_constants["USER_WAIT"])
    status = "PASSED" if is_action_set else "FAILED"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Get IP Blacklist Global settings
    test_name = "Get IP Blacklist global settings - ENABLED."
    shieldx_logger.info(test_name)
    global_settings = blacklist.get_ip_blacklist_global_settings()
    shieldx_logger.info("IP Blacklist Global Setttings: {}".format(global_settings))
    status = "QTAD-5378"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Send traffic and expect the traffic go through (Response Action: Alert Only).
    test_name = "Send traffic and expect the traffic go through (Response Action: Alert Only)."
    shieldx_logger.info(test_name)
    stats = breaking_point.send_strikes_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)
    status = "PASSED" if int(stats["total_blocked"]) == 0 else "FAILED"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Cleanup - Disable IP Blacklist.
    test_name = "Cleanup - Disable IP Blacklist."
    shieldx_logger.info(test_name)
    is_disabled = blacklist.disable_ip_blacklist()
    time.sleep(2 * shieldx_constants["USER_WAIT"])
    status = "PASSED" if is_disabled else "FAILED"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

    # Get IP Blacklist Global settings
    test_name = "Get IP Blacklist global settings - DISABLED."
    shieldx_logger.info(test_name)
    global_settings = blacklist.get_ip_blacklist_global_settings()
    shieldx_logger.info("IP Blacklist Global Setttings: {}".format(global_settings))
    status = "QTAD-5378"
    result = [build, sps_name, test_name, status]
    shieldx_results.add(result)

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_ipblacklist.py -v --setup-show -s --shieldx --branch SxRel2.1 -m blacklist_bats
#  python3 -m pytest shieldxqe/test/func/test_ipblacklist.py -v --setup-show -s --shieldx --branch SxRel2.1 --um <umip> --username <user> --password <passwd> -m blacklist_bats
