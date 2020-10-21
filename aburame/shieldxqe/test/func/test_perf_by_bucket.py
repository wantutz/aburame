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

# shieldx - ixia management
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

# shieldx - common
from sxswagger.common.custom_results import CustomResults as Result_Mgmt

@pytest.mark.perf_testing
@pytest.mark.parametrize(
    "tpp_name, bucket_size, traffic_profile", [
        # TPP Name, Bucket Size, BP Traffic Profile
        ("All Threats", 3, "SxDevOnly_TputTest1"),
    ]
)
def test_perf_by_bucket(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    tpp_name, bucket_size, traffic_profile,
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

    # Get the system info
    system_info = sys_mgmt.get_system_info()
    software_version = system_info["version"]
    content_version = system_info["contentVersion"]
    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Get the license info
    license_info = sys_mgmt.get_license()
    cpty = license_info["expected_capacity"]

    # Save snapshots for reporting
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_BUCKET_REPO"])
    column_names = ["Build", "Test Name - Iteration - Internal ID", "SPS", "Cpty", "AvgTxRate(Mbps)", "AvgRxRate(Mbps)", "AvgTCPResp(ms)", "ShieldX Rules", "Action"]
    column_widths = [26, 54, 20, 6, 16, 16, 16, 34, 8]

    # Result Manager
    shieldx_results = Result_Mgmt(result_dir, column_names, column_widths)

    # Policies
    from_tpp_name = tpp_name
    to_tpp_name = "Bucket TPP"
    sps_name = "Bucket SPS"

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

    # Delete obsolete SPS
    sps = sps_mgmt.get_sps_by_name(sps_name)
    if sps is not None:
        sps_id = sps["id"]
        is_deleted = sps_mgmt.delete_security_policy_set_by_id(sps_id)
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        assert is_deleted, "Unable to delete obsolete SPS."
    else:
        pass

    # Delete obsolete TPP
    tpp = tpp_mgmt.get_threat_prevention_policy_by_name(to_tpp_name)
    if tpp is not None:
        tpp_id = tpp["id"]
        is_deleted = tpp_mgmt.delete_threat_prevention_policy_by_id(tpp_id)
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        assert is_deleted, "Unable to delete obsolete TPP."
    else:
        pass

    # Fetch the TPP and SPS payloads from a config file
    tpp_config_file = "tpp.json"
    file_name = str((datadir/tpp_config_file).resolve())
    with open(file_name, 'r') as config_file:
        tpp_config = json.load(config_file)

        # Get the payload for cloning
        if "tpp_clone_payload" in tpp_config:
            tpp_clone_payload = tpp_config["tpp_clone_payload"]
            shieldx_logger.info("TPP Clone Payload: {}".format(tpp_clone_payload))
        else:
            assert False, "Missing TPP payload in JSON file."

    # Fetch the TPP and SPS payloads from a config file
    sps_config_file = "sps.json"
    file_name = str((datadir/sps_config_file).resolve())
    with open(file_name, 'r') as config_file:
        sps_config = json.load(config_file)

        # Get the payload for cloning
        if "sps_create_payload" in sps_config:
            sps_create_payload = sps_config["sps_create_payload"]
            shieldx_logger.info("SPS Create Payload: {}".format(sps_create_payload))
        else:
            assert False, "Missing SPS payload in JSON file."

    #### Process source TPP
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

    # Populate the payloads, do the check before proceeding
    if tpp_clone_payload:
        tpp_clone_payload["name"] = to_tpp_name
        tpp_clone_payload["tenantId"] = 1 # this should be fetched
        app_names = [app["name"] for app in apps]
    else:
        assert False, "Check JSON, needed for cloning TPP."

    if sps_create_payload is not None:
        sps_create_payload["name"] = sps_name
    else:
        assert False, "Check JSON, needed for creating SPS."

    # Use slices of the threats for testing
    index = 0
    upper_limit = len(threats)
    while (index + bucket_size) <= upper_limit:
        upper_bound = index + bucket_size
        if upper_bound > upper_limit:
            upper_bound = upper_limit
        else:
            pass

        threat_slice = threats[index:upper_bound]
        shieldx_logger.critical("Threat Slice: {}".format(threat_slice))

        # Populate rules
        tpp_clone_payload["rules"] = [{"appNames": app_names, "specificThreats": threat_slice}]

        # Clone TPP
        to_tpp_id = tpp_mgmt.create_threat_prevention_policy(tpp_clone_payload)
        shieldx_logger.info("TPP ID: {}".format(to_tpp_id))
        assert to_tpp_id > 0, "TPP creation failed."

        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Create SPS
        sps_create_payload["threatPreventionPolicyName"] = to_tpp_name
        sps_create_payload["threatPreventionPolicyId"] = to_tpp_id
        sps_id = sps_mgmt.create_security_policy_set(sps_create_payload)
        shieldx_logger.info("SPS ID: {}".format(sps_id))
        assert sps_id > 0, "SPS creation failed."

        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Assign SPS to ACL (default)
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

            assert is_updated == True, "Unable to update ACL."
        else:
            assert False, "Not able to find ACL."

        # Wait for the Policy to be updated, do with jobs to check when update is done
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Send traffic
        processed_stats = breaking_point.send_perf_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

        # Record result
        sx_rules = [("{}:{}".format(threat["protocolID"], threat["threatID"])) for threat in threat_slice]
        shieldx_logger.critical("Threat Slice: {}".format(sx_rules))

        test_model_id_iter = "{} - {} - {}".format(
            processed_stats["model_name"],
            processed_stats["test_iteration"],
            processed_stats["test_id"]
        )

        result = [
            build,
            test_model_id_iter,
            sps_name,
            cpty,
            processed_stats["avg_tx_tput"],
            processed_stats["avg_rx_tput"],
            processed_stats["avg_tcp_response_time"],
            str(sx_rules),
            ""
        ]

        # Add result
        shieldx_results.add(result)

        # Clear SPS from ACL Policy
        if acl_policy is not None:
            shieldx_logger.info("Cleanup SPS in ACL.")
            # Modify the ACL Rule in the Default ACL Policy
            acl_policy["spsId"] = "null"
            acl_policy["aclRules"][0]["spsId"] = "null"

            # Update the ACL
            shieldx_logger.info("Update ACL: {}".format(acl_policy))
            is_updated = acl_mgmt.update_acl(acl_policy)

            assert is_updated == True, "Unable to update ACL."
        else:
            assert False, "Not able to find ACL."

        # Delete SPS
        is_deleted = sps_mgmt.delete_security_policy_set_by_id(sps_id)
        assert is_deleted, "SPS delete failed."

        # Delete TPP
        is_deleted = tpp_mgmt.delete_threat_prevention_policy_by_id(to_tpp_id)
        assert is_deleted, "TPP delete failed."
        
        # Move to next slice
        index = index + bucket_size
 
@pytest.mark.perf_testing
@pytest.mark.parametrize(
    "tpp_name, bucket_size, threats_only, traffic_profile, expected_tput", [
        # TPP Name, Bucket Size, Test Threats Only, BP Traffic Profile, Expected Tput
#        ("sxLAMP", 50, True, "SxDevOnly_TputTest1", [2000.0, 2000.0]),
        ("All Threats", 3, True, "SxDevOnly_TputTest1", [2000.0, 2000.0]),
    ]
)
def test_perf_by_cumulative_bucket(
    sut_handle, ixia_handle,
    shieldx_constants, shieldx_logger,
    tpp_name, bucket_size, threats_only,
    traffic_profile, expected_tput,
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

    # Get the system info
    system_info = sys_mgmt.get_system_info()
    software_version = system_info["version"]
    content_version = system_info["contentVersion"]
    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Get the license info
    license_info = sys_mgmt.get_license()
    cpty = license_info["expected_capacity"]

    # Save snapshots for reporting
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_BUCKET_REPO"])
    column_names = ["Build", "Test Name - Iteration - Internal ID", "SPS", "Cpty", "AvgTxRate(Mbps)", "AvgRxRate(Mbps)", "AvgTCPResp(ms)", "Rules Under Test", "Action", "BcktSize"]
    column_widths = [26, 54, 20, 6, 16, 16, 16, 36, 8, 8]

    # Result Manager
    shieldx_results = Result_Mgmt(result_dir, column_names, column_widths)

    # Policies
    from_tpp_name = tpp_name
    to_tpp_name = "Cumulative TPP"
    sps_name = "Cumulative SPS"

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

    # Delete obsolete SPS
    sps = sps_mgmt.get_sps_by_name(sps_name)
    if sps is not None:
        sps_id = sps["id"]
        is_deleted = sps_mgmt.delete_security_policy_set_by_id(sps_id)
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        assert is_deleted, "Unable to delete obsolete SPS."
    else:
        pass

    # Delete obsolete TPP
    tpp = tpp_mgmt.get_threat_prevention_policy_by_name(to_tpp_name)
    if tpp is not None:
        tpp_id = tpp["id"]
        is_deleted = tpp_mgmt.delete_threat_prevention_policy_by_id(tpp_id)
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        assert is_deleted, "Unable to delete obsolete TPP."
    else:
        pass

    # Fetch the TPP and SPS payloads from a config file
    tpp_config_file = "tpp.json"
    file_name = str((datadir/tpp_config_file).resolve())
    with open(file_name, 'r') as config_file:
        tpp_config = json.load(config_file)

        # Get the payload for cloning
        if "tpp_clone_payload" in tpp_config:
            tpp_clone_payload = tpp_config["tpp_clone_payload"]
            shieldx_logger.info("TPP Clone Payload: {}".format(tpp_clone_payload))
        else:
            assert False, "Missing TPP payload in JSON file."

    # Fetch the TPP and SPS payloads from a config file
    sps_config_file = "sps.json"
    file_name = str((datadir/sps_config_file).resolve())
    with open(file_name, 'r') as config_file:
        sps_config = json.load(config_file)

        # Get the payload for cloning
        if "sps_create_payload" in sps_config:
            sps_create_payload = sps_config["sps_create_payload"]
            shieldx_logger.info("SPS Create Payload: {}".format(sps_create_payload))
        else:
            assert False, "Missing SPS payload in JSON file."

    #### Process source TPP
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

    # Populate the payloads, do the check before proceeding
    if tpp_clone_payload:
        tpp_clone_payload["name"] = to_tpp_name
        tpp_clone_payload["tenantId"] = 1 # this should be fetched
        app_names = [app["name"] for app in apps]
    else:
        assert False, "Check JSON, needed for cloning TPP."

    if sps_create_payload is not None:
        sps_create_payload["name"] = sps_name
    else:
        assert False, "Check JSON, needed for creating SPS."

    # Check flag if we want to include apps in TPP
    if threats_only:
        app_names = []
    else:
        pass

    # Use slices of the threats for testing
    index = 0
    upper_limit = len(threats)
    cumulative_ok_rules = []
    while index <= upper_limit:
        upper_bound = index + bucket_size
        if upper_bound > upper_limit:
            upper_bound = upper_limit
        else:
            pass

        threat_slice = threats[index:upper_bound]
        shieldx_logger.critical("Threat Slice: {}".format(threat_slice))

        # merge new slice to accumulated rules
        merged_list = cumulative_ok_rules + threat_slice

        # Populate rules
        tpp_clone_payload["rules"] = [{"appNames": app_names, "specificThreats": merged_list}]
        shieldx_logger.critical("Cumulative Bucket: {}".format(merged_list))

        # Clone TPP
        to_tpp_id = tpp_mgmt.create_threat_prevention_policy(tpp_clone_payload)
        shieldx_logger.info("TPP ID: {}".format(to_tpp_id))
        assert to_tpp_id > 0, "TPP creation failed."

        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Create SPS
        sps_create_payload["threatPreventionPolicyName"] = to_tpp_name
        sps_create_payload["threatPreventionPolicyId"] = to_tpp_id
        sps_id = sps_mgmt.create_security_policy_set(sps_create_payload)
        shieldx_logger.info("SPS ID: {}".format(sps_id))
        assert sps_id > 0, "SPS creation failed."

        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Assign SPS to ACL (default)
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

            assert is_updated == True, "Unable to update ACL."
        else:
            assert False, "Not able to find ACL."

        # Wait for the Policy to be updated, do with jobs to check when update is done
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Send traffic
        processed_stats = breaking_point.send_perf_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

        # Record result
        sx_rules = [("{}:{}".format(threat["protocolID"], threat["threatID"])) for threat in threat_slice]

        if processed_stats["avg_tx_tput"] >= expected_tput[0] and \
           processed_stats["avg_rx_tput"] >= expected_tput[1]:
            cumulative_ok_rules.extend(threat_slice)
            act_on_slice = "INCLUDE"
            shieldx_logger.info("These rules PASS: {}".format(sx_rules))
        else:
            act_on_slice = "EXCLUDE"
            shieldx_logger.critical("These rules FAIL: {}".format(sx_rules))

        test_model_id_iter = "{} - {} - {}".format(
            processed_stats["model_name"],
            processed_stats["test_iteration"],
            processed_stats["test_id"]
        )

        # format rules to display
        if len(threat_slice) > 3:
            display_rules = "{} + {} rules".format(sx_rules[0:2], len(sx_rules)-2)
        else:
            display_rules = str(sx_rules)

        result = [
            build,
            test_model_id_iter,
            sps_name,
            cpty,
            processed_stats["avg_tx_tput"],
            processed_stats["avg_rx_tput"],
            processed_stats["avg_tcp_response_time"],
            display_rules,
            act_on_slice,
            len(cumulative_ok_rules)
        ]

        # Add result
        shieldx_results.add(result)

        # Clear SPS from ACL Policy
        if acl_policy is not None:
            shieldx_logger.info("Cleanup SPS in ACL.")
            # Modify the ACL Rule in the Default ACL Policy
            acl_policy["spsId"] = "null"
            acl_policy["aclRules"][0]["spsId"] = "null"

            # Update the ACL
            shieldx_logger.info("Update ACL: {}".format(acl_policy))
            is_updated = acl_mgmt.update_acl(acl_policy)

            assert is_updated == True, "Unable to update ACL."
        else:
            assert False, "Not able to find ACL."

        # Delete SPS
        is_deleted = sps_mgmt.delete_security_policy_set_by_id(sps_id)
        assert is_deleted, "SPS delete failed."

        # Wait for the change to be applied
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Delete TPP
        is_deleted = tpp_mgmt.delete_threat_prevention_policy_by_id(to_tpp_id)
        assert is_deleted, "TPP delete failed."

        # Wait for the change to be applied
        time.sleep(10 * shieldx_constants["USER_WAIT"])

        # Move to next slice
        index = index + bucket_size

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_perf_by_bucket.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
