# standard library
import json
import pytest
import time

# shieldx - policy management
from sxswagger.sxapi.policy_management import AccessControl as ACL_Mgmt
from sxswagger.sxapi.policy_management import SecurityPolicySets as SPS_Mgmt
from sxswagger.sxapi.policy_management import ThreatPrevention as TPP_Mgmt

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - elastic search
from sxswagger.sxapi.elastic_search import ElasticSearch as ES

# shieldx - ixia management
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

# shieldx - common
from sxswagger.common.custom_results import CustomResults as Result_Mgmt

@pytest.mark.customer_testing
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

    #### Apply desired license
    shieldx_license = pytestconfig.getoption("license")
    is_license_set = sys_mgmt.set_license(shieldx_license)

    assert is_license_set == True, "Unable to set license."

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
        time.sleep(20 * shieldx_constants["USER_WAIT"])

        assert is_updated == True, "Unable to update ACL."
    else:
        assert False, "Not able to find ACL."

@pytest.mark.customer_testing
@pytest.mark.parametrize(
    "content_bundle", [
        # Content Bundle
        ("updatebundle_2.1.45_ce.tgz"),
        ("updatebundle_2.1.48_ce.tgz"),
    ]
)
@pytest.mark.parametrize("run_index", range(3))
def test_threat_detection_after_content_update(
    sut_handle,
    shieldx_constants, shieldx_logger,
    run_index, content_bundle,
    datadir, pytestconfig
):
    """
    Use case: Update content; then check ES that detection continues
              Frog threat traffic is running continuously
    """
    # Initialize
    sps_mgmt = SPS_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    es = ES(sut_handle)

    # Save snapshots for reporting
    result_dir = "./"
    column_names = ["Build", "Test Name", "SPS", "Cpty", "Threat Detection?"]
    column_widths = [26, 36, 26, 6, 18]
    # Result Manager
    shieldx_results = Result_Mgmt(result_dir, column_names, column_widths)

    #### File based content update
    resolved_filename = str((datadir/content_bundle).resolve())
    shieldx_logger.info("Filename: {}".format(resolved_filename))

    is_content_update_initiated = sys_mgmt.file_based_update_content(resolved_filename)
    time.sleep(20 * shieldx_constants["USER_WAIT"])

    assert is_content_update_initiated == True, "Failed to initiate content update."

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

    assert sps is not None, "Init Check - SPS must not be empty."

    # Proceed with test, get current SPS name
    sps_name = sps["name"]

    # ES Index
    index = "shieldxevents"
    # Query - head
    head = get_index_payload(index)

    # Check ES
    check_es_count = 3
    for es_check in range(check_es_count):
        shieldx_logger.info("Checking ES for threats, attempt {}".format(es_check))

        # Check threat detection in the last 10 minutes
        time.sleep(10 * shieldx_constants["USER_WAIT"])
        # End time (ms) - now
        end_time = es.get_ms_timstamp()
        # Start time (ms) - 10 minutes ago
        start_time = end_time - (10 * 60000)
        # Query - body
        body = get_threat_detection_payload(start_time, end_time)

        # Query - payload is head + body
        payload = json.dumps(head) + "\n" + json.dumps(body)

        # Fetch results from ES
        es_results = es.multi_search_query(payload)
        hits = es_results["responses"][0]["hits"]["hits"]
        for hit in hits:
            event = hit["_source"]["event"]
            shieldx_logger.info("Threat Detected - {}:{} - {}".format(event["pmId"], event["appId"], event["threatName"]))

        if len(hits) > 0:
            threat_detection = "PASS"
            shieldx_logger.info("Detection is OK, continue monitoring.")
        else:
            threat_detection = "FAIL"
            shieldx_logger.critical("Detection stopped, abort test and check setup.")

        # Results - ShieldX
        shieldx_logger.info("Software: {}".format(software_version))
        shieldx_logger.info("Content: {}".format(content_version))
        shieldx_logger.info("License: {}".format(license_info))
        shieldx_logger.info("SPS: {}".format(sps_name))

        build = "Mgmt{}Content{}".format(software_version, content_version)
        cpty = license_info["expected_capacity"]
        use_case = "Threat detection after update"

        sx_result = [
            build,
            use_case,
            sps_name,
            cpty,
            threat_detection
        ]

        # Add result
        shieldx_logger.info("Result: {}".format(sx_result))
        shieldx_results.add(sx_result)

        if threat_detection == "PASS":
            pass
        else:
            pytest.exit("Detection stopped, abort test and check setup.")

    shieldx_logger.info("Test complete.")

@pytest.mark.customer_testing
@pytest.mark.parametrize(
    "content_bundle, traffic_profile, expected_percent_blocked", [
        # Content Bundle, Traffic Profile, Expected % blocked
        ("updatebundle_2.1.45_ce.tgz", "SxSecurityTest_BATS", 95.0),
        ("updatebundle_2.1.48_ce.tgz", "SxSecurityTest_BATS", 95.0),
    ]
)
@pytest.mark.parametrize("run_index", range(3))
def test_bp_detection_and_blocking_after_content_update(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    run_index, content_bundle, traffic_profile, expected_percent_blocked,
    datadir, pytestconfig
):
    """
    Use case: Update content; then check BP that threats are detected and blocked
    """
    # Initialize
    # DUT
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)
    acl_mgmt = ACL_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)
    es = ES(sut_handle)
    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    #### File based content update
    resolved_filename = str((datadir/content_bundle).resolve())
    shieldx_logger.info("Filename: {}".format(resolved_filename))

    is_content_update_initiated = sys_mgmt.file_based_update_content(resolved_filename)
    shieldx_logger.critical("Waiting for the compilation to finish!!!")
    time.sleep(20 * shieldx_constants["USER_WAIT"])
    assert is_content_update_initiated == True, "Failed to initiate content update."

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

    # Check - proceed only if init setup is done
    assert sps is not None, "Check strikes test init, SPS must not be empty."
    # Proceed with test, get current SPS name
    sps_name = sps["name"]

    # ES Index
    index = "shieldxevents"
    # Query - head
    head = get_index_payload(index)

    # Start time (ms) - now
    start_time = es.get_ms_timstamp()

    # Send traffic
    processed_stats = breaking_point.send_strikes_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

    # End time (ms) - now + 30secs
    end_time = es.get_ms_timstamp() + 30000

    # Query - body
    body = get_threat_detection_payload(start_time, end_time)

    # Query - payload is head + body
    payload = json.dumps(head) + "\n" + json.dumps(body)

    # Fetch results from ES
    es_results = es.multi_search_query(payload)
    hits = es_results["responses"][0]["hits"]["hits"]
    for hit in hits:
        event = hit["_source"]["event"]
        shieldx_logger.info("Threat Detected - {}:{} - {}".format(event["pmId"], event["appId"], event["threatName"]))

    if len(hits) > 0:
        threat_detection = "PASS"
        shieldx_logger.info("Detection is OK, continue monitoring.")
    else:
        threat_detection = "FAIL"
        shieldx_logger.critical("Detection stopped, abort test and check setup.")

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
    shieldx_results = Result_Mgmt(result_dir, column_names, column_widths)
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
    # Abort test if a threat is not detected
    if float(percent_blocked) < float(expected_percent_blocked):
        pytest.exit("Not all threats are detected, abort and check the setup.")
    else:
        pass

@pytest.mark.customer_testing
def test_clean_setup(
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


@pytest.mark.customer_testing
@pytest.mark.parametrize(
    "content_bundle, traffic_profile, expected_percent_blocked", [
        # Content Bundle, Traffic Profile, Expected % blocked
        ("updatebundle_2.1.101_ce.tgz", "SxSecurityTest_BATS", 100),
        ("updatebundle_2.1.32_ce.tgz", "SxSecurityTest_BATS", 100),
    ]
)
def test_policy_clone_and_threat_detection(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    content_bundle, traffic_profile, expected_percent_blocked,
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

    #### File based content update
    resolved_filename = str((datadir/content_bundle).resolve())
    shieldx_logger.info("Filename: {}".format(resolved_filename))

    is_content_update_initiated = sys_mgmt.file_based_update_content(resolved_filename)
    time.sleep(20 * shieldx_constants["USER_WAIT"])

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
        time.sleep(20 * shieldx_constants["USER_WAIT"])

        assert is_updated == True, "Unable to update ACL."
    else:
        assert False, "Not able to find ACL."

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
    shieldx_results = Result_Mgmt(result_dir, column_names, column_widths)
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

    # Pass/Fail Test
    assert percent_blocked == 100.0, "Not all threats are detected, abort and check the setup."

def get_index_payload(index):
    payload = {
        "index": index,
        "ignore_unavailable": True,
    }

    return payload

def get_threat_detection_payload(start_time, end_time):
    payload = {
        "size": 10,
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": "doctype:DPI AND event.eventType:5", "analyze_wildcard": True}},
                    {"range": {"timeStamp": {"gte": start_time, "lte": end_time, "format": "epoch_millis"}}}
                ],
            }
        }
    }

    return payload

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_detection_after_update.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
