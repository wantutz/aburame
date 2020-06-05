# standard library
import copy
import json
import pytest
import time

# shieldx - policy management
from sxswagger.sxapi.policy_management import AccessControl as ACL_Mgmt
from sxswagger.sxapi.policy_management import Malware as MalwareMgmt
from sxswagger.sxapi.policy_management import SecurityPolicySets as SPS_Mgmt
from sxswagger.sxapi.policy_management import ThreatPrevention as TPP_Mgmt

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - ixia management
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

# shieldx - common
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR
from sxswagger.common.custom_results import CustomResults as ResultsMgmt

@pytest.mark.strikes_testing
def test_init_setup(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    # DUT
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)
    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    # Policies
    from_tpp_name = "All Threats"
    to_tpp_name = "All Threats Blocked TPP"
    sps_name = "All Threats Blocked SPS"

    #### Clear SPS from ACL Policy
    is_updated = False
    default_acl = "Default ACL Policy"
    acl_policy = acl_mgmt.get_acl_by_name(default_acl)
    if acl_policy is not None:
        # Modify the ACL Rule in the Default ACL Policy
        acl_policy["spsId"] = "null"
        acl_policy["aclRules"][0]["spsId"] = "null"

        # Update the ACL
        shieldx_logger.info("Update ACL: {}".format(acl_policy))
        is_updated = acl_mgmt.update_acl(acl_policy)

        assert is_updated == True, "Unable to update ACL."
    else:
        assert False, "Not able to find ACL."

    #### Delete obsolete SPS
    sps = sps_mgmt.get_sps_by_name(sps_name)
    shieldx_logger.info("Obsolete SPS: {}".format(sps))
    if sps is not None:
        sps_id = sps["id"]
        is_deleted = sps_mgmt.delete_security_policy_set_by_id(sps_id)

        assert is_deleted == True, "Unable to delete old SPS."
    else:
        # No-op
        pass

    #### Delete obsolete TPP
    tpp = tpp_mgmt.get_threat_prevention_policy_by_name(to_tpp_name)
    shieldx_logger.info("Obsolete TPP: {}".format(tpp))
    if tpp is not None:
        to_tpp_id = tpp["id"]
        is_deleted = tpp_mgmt.delete_threat_prevention_policy_by_id(to_tpp_id)

        assert is_deleted == True, "Unable to delete old TPP."
    else:
        # No-op
        pass

    #### Apply desired license
    shieldx_license = pytestconfig.getoption("license")
    is_license_set = sys_mgmt.set_license(shieldx_license)

    assert is_license_set == True, "Unable to set license."

    #### Download latest content - based on license
    is_content_update_initiated = sys_mgmt.update_content()
    time.sleep(15 * shieldx_constants["USER_WAIT"])

    assert is_content_update_initiated == True, "Failed to initiate content update."

    #### Clone "All Threats" and set Response to BLOCK
    block_threats = True
    from_tpp_id = None
    to_tpp_id = None

    threats = None
    apps = None

    # Get Threat Prevention Policy
    tpp = tpp_mgmt.get_threat_prevention_policy_by_name(from_tpp_name)
    from_tpp_id = tpp["id"]

    if from_tpp_id is not None:
        threats = tpp_mgmt.get_threats_by_policy_id(from_tpp_id)
        apps = tpp_mgmt.get_apps_by_policy_id(from_tpp_id)
        shieldx_logger.info("TPP Name: {}".format(from_tpp_name))
        shieldx_logger.info("TPP ID: {}".format(from_tpp_id))
    else:
        shieldx_logger.error("Unable to find the  TPP.")

    # Fetch the payload from a config file
    tpp_config_file = "tpp.json"
    file_name = str((datadir/tpp_config_file).resolve())
    with open(file_name, 'r') as config_file:
        tpp_config = json.load(config_file)

        # Get the payload for cloning
        if "tpp_clone_payload" in tpp_config:
            clone_payload = tpp_config["tpp_clone_payload"]
            shieldx_logger.info("Clone Payload: {}".format(clone_payload))
        else:
            pass

        # Get the payload for response action
        if "tpp_bulk_edit_response_payload" in tpp_config:
            response_payload = tpp_config["tpp_bulk_edit_response_payload"]
            shieldx_logger.info("Bulk Edit Payload: {}".format(response_payload))
        else:
            pass

    # Populate the payload
    if clone_payload:
        clone_payload["name"] = to_tpp_name
        clone_payload["tenantId"] = 1 # this should be fetched
        app_names = [app["name"] for app in apps]

        # Special handling based on the policy being cloned
        # Option is based on "Uses Specific Threats?" flag
        # This flag is based whether "specificThreats" is populated.
        if from_tpp_name == "Common Threats" or from_tpp_name == "AppVisibility":
            # no need to specify the "appNames" in the rules.
            # specify the "specificThreats" instead
            clone_payload["rules"] = [{"specificThreats": threats}]
        else:
            # no need to specify the "specificThreats" in the rules.
            # specify the "appNames" instead
            if app_names:
                clone_payload["rules"] = [{"appNames": app_names}]
            else:
                clone_payload["rules"] = []
    else:
        shieldx_logger.error("Unable to fetch the TPP payload from config file.")

    # Create a clone of a TPP, get the TPP ID back
    to_tpp_id = tpp_mgmt.create_threat_prevention_policy(clone_payload)
    shieldx_logger.info("Create OK, TPP ID: {}".format(to_tpp_id))

    assert to_tpp_id != 0, "TPP Clone failed."

    # Clone TPP responses
    is_cloned = tpp_mgmt.clone_threat_prevention_policy_responses(
                  from_tpp_id, to_tpp_id)

    assert is_cloned == True, "Clone TPP responses failed."

    # Bulk Edit - Block threats
    if block_threats:
        threat_responses = tpp_mgmt.get_threat_responses_by_policy_id(to_tpp_id)
        for threat_response in threat_responses:
            threat_response["block"] = True
            threat_response["policyId"] = to_tpp_id

        response_payload["id"] = to_tpp_id
        response_payload["responses"] = threat_responses

        shieldx_logger.info("Bulk Edit Payload: {}".format(response_payload))
        bulk_edit_success = tpp_mgmt.bulk_update_threat_responses(response_payload)

        assert bulk_edit_success == True, "Bulk edit response action failed."
    else:
        pass

    #### Create "All Threats Blocked SPS"
    sps_id = 0
    # Fetch the payload from a config file
    sps_config_file = "sps.json"
    file_name = str((datadir/sps_config_file).resolve())
    with open(file_name, 'r') as config_file:
        sps_config = json.load(config_file)

        # Get the payload for cloning
        if "sps_create_payload" in sps_config:
            create_payload = sps_config["sps_create_payload"]
            shieldx_logger.info("Create Payload: {}".format(create_payload))
        else:
            create_payload = None

    if create_payload is not None:
        create_payload["name"] = sps_name
        create_payload["threatPreventionPolicyName"] = to_tpp_name
        create_payload["threatPreventionPolicyId"] = to_tpp_id

        shieldx_logger.info("Create Payload: {}".format(create_payload))
        sps_id = sps_mgmt.create_security_policy_set(create_payload)

        assert sps_id > 0, "SPS creation failed."
    else:
        pass

    #### Apply SPS to ACL
    is_updated = False
    default_acl = "Default ACL Policy"
    acl_policy = acl_mgmt.get_acl_by_name(default_acl)

    if acl_policy is not None:
        shieldx_logger.info("Update ACL with SPS Name: {}".format(sps_name))
        shieldx_logger.info("Update ACL with SPS ID: {}".format(sps_id))
        # Modify the ACL Rule in the Default ACL Policy
        acl_policy["spsId"] = sps_id
        acl_policy["aclRules"][0]["spsId"] = sps_id

        # Update the ACL
        shieldx_logger.info("Update ACL: {}".format(acl_policy))
        is_updated = acl_mgmt.update_acl(acl_policy)

        # Compile and propagate config
        time.sleep(15 * shieldx_constants["USER_WAIT"])

        assert is_updated == True, "Unable to update ACL."
    else:
        assert False, "Not able to find ACL."
    

@pytest.mark.strikes_testing
@pytest.mark.parametrize(
    "traffic_profile, expected_percent_blocked", [
        # BP Traffic Profile, % BLOCKED
        ("SxSecurityTest_BATS", 100),
        ("SxSecurityTest_NoSSL_C2S_2010", 70),
        ("SxSecurityTest_NoSSL_C2S_2011", 70),
        ("SxSecurityTest_NoSSL_C2S_2012", 70),
        ("SxSecurityTest_NoSSL_C2S_2013", 70),
        ("SxSecurityTest_NoSSL_C2S_2014", 70),
        ("SxSecurityTest_NoSSL_C2S_2015", 70),
        ("SxSecurityTest_NoSSL_C2S_2016", 70),
        ("SxSecurityTest_NoSSL_C2S_2017", 70),
        ("SxSecurityTest_NoSSL_C2S_2018", 70),
        ("SxSecurityTest_NoSSL_C2S_2019", 70),
        ("SxSecurityTest_NoSSL_C2S_2020", 70),
        ("SxSecurityTest_NoSSL_S2C_2010", 70),
        ("SxSecurityTest_NoSSL_S2C_2011", 70),
        ("SxSecurityTest_NoSSL_S2C_2012", 70),
        ("SxSecurityTest_NoSSL_S2C_2013", 70),
        ("SxSecurityTest_NoSSL_S2C_2014", 70),
        ("SxSecurityTest_NoSSL_S2C_2015", 70),
        ("SxSecurityTest_NoSSL_S2C_2016", 70),
        ("SxSecurityTest_NoSSL_S2C_2017", 70),
        ("SxSecurityTest_NoSSL_S2C_2018", 70),
        ("SxSecurityTest_NoSSL_S2C_2019", 70),
        ("SxSecurityTest_NoSSL_S2C_2020", 70),
        ("SxSecurityTest_IPv6_BATS", 100),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2010", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2011", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2012", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2013", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2014", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2015", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2016", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2017", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2018", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2019", 70),
        ("SxSecurityTest_IPv6_NoSSL_C2S_2020", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2010", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2011", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2012", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2013", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2014", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2015", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2016", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2017", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2018", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2019", 70),
        ("SxSecurityTest_IPv6_NoSSL_S2C_2020", 70),
        ("SxSecurityTest_NoSSL_Content1_3_149", 100),
        ("SxSecurityTest_NoSSL_Content1_3_152", 100),
        ("SxSecurityTest_NoSSL_Content1_3_178", 100),
        ("SxSecurityTest_NoSSL_Content1_4_156", 100),
        ("SxSecurityTest_NoSSL_Content1_4_171", 100),
        ("SxSecurityTest_NoSSL_Content2_1_30", 100),
        ("SxSecurityTest_NoSSL_Content2_1_32", 100),
        ("SxSecurityTest_NoSSL_Content2_1_37", 100),
        ("SxSecurityTest_NoSSL_Content2_1_45", 100),
        ("SxSecurityTest_NoSSL_Content2_1_48", 100),
    ]
)
def test_strikes_by_year_and_direction(
    sut_handle, datadir, ixia_handle,
    shieldx_constants, shieldx_logger,
    traffic_profile, expected_percent_blocked
):
    # Initialize
    # DUT
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)
    # Traffic Gen
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

    assert sps is not None, "Check strikes test init, SPS must not be empty."

    # Proceed with test, get current SPS name
    sps_name = sps["name"]

    # Send traffic
    processed_stats = breaking_point.send_strikes_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

    # Results - ShieldX
    shieldx_logger.info("Software: {}".format(software_version))
    shieldx_logger.info("Content: {}".format(content_version))
    shieldx_logger.info("License: {}".format(license_info))
    shieldx_logger.info("SPS: {}".format(sps_name))
    # Results - Breaking Point
    shieldx_logger.info("BP Model Name: {}".format(processed_stats["model_name"]))
    shieldx_logger.info("BP Test ID: {}".format(processed_stats["test_id"]))
    shieldx_logger.info("BP Test Iteration: {}".format(processed_stats["test_iteration"]))
    shieldx_logger.info("Total Strikes: {}".format(processed_stats["total_strikes"]))
    shieldx_logger.info("Total Allowed: {}".format(processed_stats["total_allowed"]))
    shieldx_logger.info("Total Blocked: {}".format(processed_stats["total_blocked"]))

    # Compute percentage
    if int(processed_stats["total_strikes"]) != 0:
        percent_blocked = "{:.2f}".format(100 * (int(processed_stats["total_blocked"]) / int(processed_stats["total_strikes"])))
    else:
        percent_blocked = "0.0"

    # Save snapshots for reporting
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_STRIKES_REPO"])
    column_names = ["Build", "Test Name - Iteration - Internal ID", "SPS", "Cpty", "Total Strikes", "Total Allowed", "Total Blocked", "% Blocked"]
    column_widths = [26, 54, 26, 6, 14, 14, 14, 10]

    build = "Mgmt{}Content{}".format(software_version, content_version)
    test_model_id_iter = "{} - {} - {}".format(
        processed_stats["model_name"],
        processed_stats["test_iteration"],
        processed_stats["test_id"]
    )

    cpty = license_info["expected_capacity"]

    # Prep result
    shieldx_results = ResultsMgmt(result_dir, column_names, column_widths)
    result = [
        build,
        test_model_id_iter,
        sps_name,
        cpty,
        processed_stats["total_strikes"],
        processed_stats["total_allowed"],
        processed_stats["total_blocked"],
        percent_blocked
    ]

    # Add result
    shieldx_results.add(result)

    # Pass/Fail Test

@pytest.mark.strikes_testing
def test_del_setup(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    # DUT
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)
    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    # Policies
    from_tpp_name = "All Threats"
    to_tpp_name = "All Threats Blocked TPP"
    sps_name = "All Threats Blocked SPS"

    #### Clear SPS from ACL Policy
    is_updated = False
    default_acl = "Default ACL Policy"
    acl_policy = acl_mgmt.get_acl_by_name(default_acl)
    if acl_policy is not None:
        # Modify the ACL Rule in the Default ACL Policy
        acl_policy["spsId"] = "null"
        acl_policy["aclRules"][0]["spsId"] = "null"

        # Update the ACL
        shieldx_logger.info("Update ACL: {}".format(acl_policy))
        is_updated = acl_mgmt.update_acl(acl_policy)

        assert is_updated == True, "Unable to update ACL."
    else:
        assert False, "Not able to find ACL."

    #### Delete obsolete SPS
    sps = sps_mgmt.get_sps_by_name(sps_name)
    shieldx_logger.info("Obsolete SPS: {}".format(sps))
    if sps is not None:
        sps_id = sps["id"]
        is_deleted = sps_mgmt.delete_security_policy_set_by_id(sps_id)

        assert is_deleted == True, "Unable to delete old SPS."
    else:
        # No-op
        pass

    #### Delete obsolete TPP
    tpp = tpp_mgmt.get_threat_prevention_policy_by_name(to_tpp_name)
    shieldx_logger.info("Obsolete TPP: {}".format(tpp))
    if tpp is not None:
        to_tpp_id = tpp["id"]
        is_deleted = tpp_mgmt.delete_threat_prevention_policy_by_id(to_tpp_id)

        assert is_deleted == True, "Unable to delete old TPP."
    else:
        # No-op
        pass

@pytest.mark.strikes_testing
def test_init_malware_setup(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    # DUT
    malware_mgmt = MalwareMgmt(sut_handle)

    # Policies
    policies = malware_mgmt.get_policies()

    if policies is not None:
        for policy in policies:
            shieldx_logger.info("Malware Policy: {}".format(policy))

        # Update the default policy
        default_malware_policy_name = "WithSXCloud"
        default_malware_policy = malware_mgmt.get_policy_by_name(default_malware_policy_name)

        default_malware_policy["fileActions"]["selectedMWEngine"] = "FECLOUD"
        default_policy_id = malware_mgmt.update_policy(default_malware_policy)
        shieldx_logger.info("Default Malware Policy ID: {}".format(default_policy_id))
    else:
        shieldx_logger.error("Malware Policy not found.")

    # JSON Config Reader
    config_reader = CCR()
    malware_json = "malware.json"

    # Malware Payload - read config file
    resolved_input_json_file = str((datadir/malware_json).resolve())
    malware_payloads = dict(config_reader.read_json_config(resolved_input_json_file))

    # Create a new Malware Policy - QTAD-15358
    payload1 = copy.deepcopy(malware_payloads["malware_payload"])
    shieldx_logger.info("Malware Payload 1 - Create: {}".format(payload1))
    malware_policy_name = "WithFECloud"
    payload1["name"] = malware_policy_name
    payload1["fileActions"]["selectedMWEngine"] = "FECLOUD"
    shieldx_logger.info("Malware Payload with FE Cloud: {}".format(payload1))

    policy_id = malware_mgmt.create_policy(payload1)
    shieldx_logger.info("Policy ID: {}".format(policy_id))

    # Update a non-existent Malware Policy - QTAD-15358
    payload2 = copy.deepcopy(malware_payloads["malware_payload"])
    shieldx_logger.info("Malware Payload 2 - Update: {}".format(payload2))
    malware_policy_name = "CustomCloud"
    payload2["name"] = malware_policy_name
    payload2["fileActions"]["selectedMWEngine"] = "SXCLOUD"
    shieldx_logger.info("Malware Payload with SX Cloud: {}".format(payload2))

    policy_id = malware_mgmt.update_policy(payload2)
    shieldx_logger.info("Policy ID: {}".format(policy_id))

@pytest.mark.strikes_testing
def test_del_malware_setup(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    # DUT
    malware_mgmt = MalwareMgmt(sut_handle)

    # Get the newly created Malware Policy
    malware_policy_name = "WithFECloud"
    new_policy = malware_mgmt.get_policy_by_name(malware_policy_name)

    # Delete the Malware Policy
    if new_policy is not None:
        policy_id = new_policy["id"]

        is_deleted = malware_mgmt.delete_policy(policy_id)
        shieldx_logger.info("Delete Malware Policy: {}".format(is_deleted))
    else:
        shieldx_logger.error("Malware Policy not found.")

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
