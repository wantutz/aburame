# standard library
import json
import pytest
import time

# shieldx - system under test
from sxswagger.sxapi.system_under_test import SystemUnderTest as SUT

# shieldx - ixia management
from sxswagger.ixia.breaking_point import BreakingPoint
from sxswagger.ixia.real_time_stats import RealTimeStats as RTS

# shieldx - common
from sxswagger.common.custom_results import CustomResults as ResultsMgmt
from sxswagger.common.custom_config_reader import CustomConfigReader

@pytest.mark.perf_testing
@pytest.mark.parametrize(
    "policy_name, traffic_profile, expected_cps", [
        # Policy Name, BP Traffic Profile, Tx and Rx in Mbps
        (None, "SxTest_Http_NN1_Cps40k_Resp1kb_Iter1", [40000.0, 40000.0]),
        ("Discover", "SxTest_Http_NN1_Cps20k_Resp1kb_Iter1", [20000.0, 20000.0]),
        ("Testing", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("All Inclusive", "SxTest_Http_NN1_Cps4k_Resp1kb_Iter1", [4000.0, 4000.0]),
    ]
)
@pytest.mark.parametrize(
    "content_bundle", [
        # Content Bundle
        ("updatebundle_2.1.509_ce.tgz"),
        ("updatebundle_2.1.510_ce.tgz"),
    ]
)
def test_perf_cps_custom_content(
        sut_handle, ixia_handle,
        shieldx_constants, shieldx_logger,
        policy_name, traffic_profile, expected_cps,
        content_bundle, datadir
):
    # SUT - System Under Test
    sut = SUT(sut_handle)

    #### File based content update
    resolved_filename = str((datadir/content_bundle).resolve())
    shieldx_logger.info("Filename: {}".format(resolved_filename))

    is_content_update_initiated = sut.update_content_by_file(resolved_filename)
    assert is_content_update_initiated, "Failed to initiate content update."

    time.sleep(20 * shieldx_constants["USER_WAIT"])

    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    # Assign SPS to ACL (default)
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, policy_name)
    assert is_updated, "Assign the SPS under test."

    # Wait for the Policy to be updated, do with jobs to check when update is done
    time.sleep(20 * shieldx_constants["USER_WAIT"])

    # Check last completed job
    job = sut.get_last_completed_job()
    shieldx_logger.info("Job: {}".format(job))

    # Audit Log - Query log between start and end time
    # End time (ms) - now
    end_time = int(round(time.time()) * 1000)
    # Start time (ms) - 20 minutes ago
    start_time = end_time - (20 * 60000)

    # Get Audit Log - filter by action
    action = "Edit"
    audit_log_entries = sut.get_audit_log_by_action(start_time, end_time, action)
    shieldx_logger.info("Log count: {}".format(len(audit_log_entries)))
    for entry in audit_log_entries:
        shieldx_logger.info("Content Update Log: {}".format(entry))

    # Send traffic - get processed stats
    processed_stats = breaking_point.send_app_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

    # Debug - BP Info
    shieldx_logger.info("BP Model Name: {}".format(processed_stats["model_name"]))
    shieldx_logger.info("BP Test ID: {}".format(processed_stats["test_id"]))
    shieldx_logger.info("BP Test Iteration: {}".format(processed_stats["test_iteration"]))
    shieldx_logger.info("Avg Tx Tput: {}".format(processed_stats["avg_tx_tput"]))
    shieldx_logger.info("Avg Rx Tput: {}".format(processed_stats["avg_rx_tput"]))
    shieldx_logger.info("Avg TCP Client Establish Rate: {}".format(processed_stats["avg_tcp_client_established_rate"]))
    shieldx_logger.info("Avg TCP Server Establish Rate: {}".format(processed_stats["avg_tcp_server_established_rate"]))
    shieldx_logger.info("Avg TCP Resp Time: {}".format(processed_stats["avg_tcp_response_time"]))

    # Get the system info
    system_info = sut.get_system_info()

    # Reporting - ShieldX Info
    software_version = system_info["software_version"]
    content_version = system_info["content_version"]
    capacity = system_info["capacity"]
    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Debug - ShieldX Info
    shieldx_logger.info("Software: {}".format(software_version))
    shieldx_logger.info("Content: {}".format(content_version))
    shieldx_logger.info("Capacity: {}".format(capacity))
    shieldx_logger.info("SPS: {}".format(policy_name))

    # Reporting - BP Test Info
    test_model_id_iter = "{} - {} - {}".format(
        processed_stats["model_name"],
        processed_stats["test_iteration"],
        processed_stats["test_id"]
    )

    # Results - Repository
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_CPS_REPO"])

    # Results - Column Names
    column_names = [
        "Build", "Test Name - Iteration - Internal ID",
        "SPS", "Cpty",
        "AvgTxRate(Mbps)", "AvgRxRate(Mbps)",
        "AvgTCPClientCPS", "AvgTCPServerCPS",
        "AvgTCPResp(ms)"
    ]

    # Results - Column Widths
    column_widths = [26, 54, 24, 6, 16, 16, 16, 16, 16]

    # Results - Initialize
    shieldx_results = ResultsMgmt(result_dir, column_names, column_widths)

    # Results - Prep entry
    result = [
        build,
        test_model_id_iter,
        str(policy_name),
        capacity,
        processed_stats["avg_tx_tput"],
        processed_stats["avg_rx_tput"],
        processed_stats["avg_tcp_client_established_rate"],
        processed_stats["avg_tcp_server_established_rate"],
        processed_stats["avg_tcp_response_time"]
    ]

    # Results - Record entry
    shieldx_logger.info("Record result: {}".format(result))
    shieldx_results.add(result)

    # Cleanup below
    # Clear SPS from ACL Policy
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, None)
    assert is_updated, "Cleanup, SPS set to none."

    # Pass/Fail Test

@pytest.mark.perf_testing
@pytest.mark.parametrize(
    "policy_name, traffic_profile, expected_cps", [
        # Policy Name, BP Traffic Profile, Tx and Rx in Mbps
        (None, "SxTest_Http_NN1_Cps40k_Resp1kb_Iter1", [40000.0, 40000.0]),
        ("Discover", "SxTest_Http_NN1_Cps20k_Resp1kb_Iter1", [20000.0, 20000.0]),
        ("Testing", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("All Inclusive", "SxTest_Http_NN1_Cps4k_Resp1kb_Iter1", [4000.0, 4000.0]),
    ]
)
def test_perf_cps_canned_sps(sut_handle, ixia_handle,
        shieldx_constants, shieldx_logger,
        policy_name, traffic_profile, expected_cps):
    # SUT - System Under Test
    sut = SUT(sut_handle)

    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    # Assign SPS to ACL (default)
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, policy_name)
    assert is_updated, "Assign the SPS under test."

    # Wait for the Policy to be updated, do with jobs to check when update is done
    time.sleep(20 * shieldx_constants["USER_WAIT"])

    # Check last completed job
    job = sut.get_last_completed_job()
    shieldx_logger.info("Job: {}".format(job))

    # Audit Log - Query log between start and end time
    # End time (ms) - now
    end_time = int(round(time.time()) * 1000)
    # Start time (ms) - 20 minutes ago
    start_time = end_time - (20 * 60000)

    # Get Audit Log - filter by action
    action = "Edit"
    audit_log_entries = sut.get_audit_log_by_action(start_time, end_time, action)
    shieldx_logger.info("Log count: {}".format(len(audit_log_entries)))
    for entry in audit_log_entries:
        shieldx_logger.info("Content Update Log: {}".format(entry))

    # Send traffic - get processed stats
    processed_stats = breaking_point.send_app_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

    # Debug - BP Info
    shieldx_logger.info("BP Model Name: {}".format(processed_stats["model_name"]))
    shieldx_logger.info("BP Test ID: {}".format(processed_stats["test_id"]))
    shieldx_logger.info("BP Test Iteration: {}".format(processed_stats["test_iteration"]))
    shieldx_logger.info("Avg Tx Tput: {}".format(processed_stats["avg_tx_tput"]))
    shieldx_logger.info("Avg Rx Tput: {}".format(processed_stats["avg_rx_tput"]))
    shieldx_logger.info("Avg TCP Client Establish Rate: {}".format(processed_stats["avg_tcp_client_established_rate"]))
    shieldx_logger.info("Avg TCP Server Establish Rate: {}".format(processed_stats["avg_tcp_server_established_rate"]))
    shieldx_logger.info("Avg TCP Resp Time: {}".format(processed_stats["avg_tcp_response_time"]))

    # Get the system info
    system_info = sut.get_system_info()

    # Reporting - ShieldX Info
    software_version = system_info["software_version"]
    content_version = system_info["content_version"]
    capacity = system_info["capacity"]
    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Debug - ShieldX Info
    shieldx_logger.info("Software: {}".format(software_version))
    shieldx_logger.info("Content: {}".format(content_version))
    shieldx_logger.info("Capacity: {}".format(capacity))
    shieldx_logger.info("SPS: {}".format(policy_name))

    # Reporting - BP Test Info
    test_model_id_iter = "{} - {} - {}".format(
        processed_stats["model_name"],
        processed_stats["test_iteration"],
        processed_stats["test_id"]
    )

    # Results - Repository
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_CPS_REPO"])

    # Results - Column Names
    column_names = [
        "Build", "Test Name - Iteration - Internal ID",
        "SPS", "Cpty",
        "AvgTxRate(Mbps)", "AvgRxRate(Mbps)",
        "AvgTCPClientCPS", "AvgTCPServerCPS",
        "AvgTCPResp(ms)"
    ]

    # Results - Column Widths
    column_widths = [26, 54, 24, 6, 16, 16, 16, 16, 16]

    # Results - Initialize
    shieldx_results = ResultsMgmt(result_dir, column_names, column_widths)

    # Results - Prep entry
    result = [
        build,
        test_model_id_iter,
        str(policy_name),
        capacity,
        processed_stats["avg_tx_tput"],
        processed_stats["avg_rx_tput"],
        processed_stats["avg_tcp_client_established_rate"],
        processed_stats["avg_tcp_server_established_rate"],
        processed_stats["avg_tcp_response_time"]
    ]

    # Results - Record entry
    shieldx_logger.info("Record result: {}".format(result))
    shieldx_results.add(result)

    # Cleanup below
    # Clear SPS from ACL Policy
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, None)
    assert is_updated, "Cleanup, SPS set to none."

    # Pass/Fail Test

@pytest.mark.perf_testing
@pytest.mark.parametrize(
    "policy_name, traffic_profile, expected_cps", [
        # TPP Name, BP Traffic Profile, Avg TCP Client and Server CPS
        ("sxDatabase_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxLAMP_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxLEMP_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxMEAN_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxMSFTP_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxNoSQLDatabase_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxRDBMSDatabase_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxTomcat_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxWAMP_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxWordPressLAMP_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("sxWordPressLEMP_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
    ]
)
def test_perf_cps_canned_tpp(
        sut_handle, datadir, ixia_handle,
        shieldx_constants, shieldx_logger,
        policy_name, traffic_profile, expected_cps):
    # SUT - System Under Test
    sut = SUT(sut_handle)

    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    # Assign SPS to ACL (default)
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, policy_name)
    assert is_updated, "Assign the SPS under test."

    # Wait for the Policy to be updated, do with jobs to check when update is done
    time.sleep(20 * shieldx_constants["USER_WAIT"])

    # Check last completed job
    job = sut.get_last_completed_job()
    shieldx_logger.info("Job: {}".format(job))

    # Audit Log - Query log between start and end time
    # End time (ms) - now
    end_time = int(round(time.time()) * 1000)
    # Start time (ms) - 20 minutes ago
    start_time = end_time - (20 * 60000)

    # Get Audit Log - filter by action
    action = "Edit"
    audit_log_entries = sut.get_audit_log_by_action(start_time, end_time, action)
    shieldx_logger.info("Log count: {}".format(len(audit_log_entries)))
    for entry in audit_log_entries:
        shieldx_logger.info("Content Update Log: {}".format(entry))

    # Send traffic - get processed stats
    processed_stats = breaking_point.send_app_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

    # Debug - BP Info
    shieldx_logger.info("BP Model Name: {}".format(processed_stats["model_name"]))
    shieldx_logger.info("BP Test ID: {}".format(processed_stats["test_id"]))
    shieldx_logger.info("BP Test Iteration: {}".format(processed_stats["test_iteration"]))
    shieldx_logger.info("Avg Tx Tput: {}".format(processed_stats["avg_tx_tput"]))
    shieldx_logger.info("Avg Rx Tput: {}".format(processed_stats["avg_rx_tput"]))
    shieldx_logger.info("Avg TCP Client Establish Rate: {}".format(processed_stats["avg_tcp_client_established_rate"]))
    shieldx_logger.info("Avg TCP Server Establish Rate: {}".format(processed_stats["avg_tcp_server_established_rate"]))
    shieldx_logger.info("Avg TCP Resp Time: {}".format(processed_stats["avg_tcp_response_time"]))

    # Get the system info
    system_info = sut.get_system_info()

    # Reporting - ShieldX Info
    software_version = system_info["software_version"]
    content_version = system_info["content_version"]
    capacity = system_info["capacity"]
    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Debug - ShieldX Info
    shieldx_logger.info("Software: {}".format(software_version))
    shieldx_logger.info("Content: {}".format(content_version))
    shieldx_logger.info("Capacity: {}".format(capacity))
    shieldx_logger.info("SPS: {}".format(policy_name))

    # Reporting - BP Test Info
    test_model_id_iter = "{} - {} - {}".format(
        processed_stats["model_name"],
        processed_stats["test_iteration"],
        processed_stats["test_id"]
    )

    # Results - Repository
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_CPS_REPO"])

    # Results - Column Names
    column_names = [
        "Build", "Test Name - Iteration - Internal ID",
        "SPS", "Cpty",
        "AvgTxRate(Mbps)", "AvgRxRate(Mbps)",
        "AvgTCPClientCPS", "AvgTCPServerCPS",
        "AvgTCPResp(ms)"
    ]

    # Results - Column Widths
    column_widths = [26, 54, 24, 6, 16, 16, 16, 16, 16]

    # Results - Initialize
    shieldx_results = ResultsMgmt(result_dir, column_names, column_widths)

    # Results - Prep entry
    result = [
        build,
        test_model_id_iter,
        str(policy_name),
        capacity,
        processed_stats["avg_tx_tput"],
        processed_stats["avg_rx_tput"],
        processed_stats["avg_tcp_client_established_rate"],
        processed_stats["avg_tcp_server_established_rate"],
        processed_stats["avg_tcp_response_time"]
    ]

    # Results - Record entry
    shieldx_logger.info("Record result: {}".format(result))
    shieldx_results.add(result)

    # Cleanup below
    # Clear SPS from ACL Policy
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, None)
    assert is_updated, "Cleanup, SPS set to none."

    # Pass/Fail Test

@pytest.mark.perf_testing
@pytest.mark.parametrize(
    "policy_name, traffic_profile, expected_cps", [
        # TPP Name, BP Traffic Profile, Avg TCP Client and Server CPS
        ("CommonThreatsWithDLP_SPS", "SxTest_Http_NN1_Cps10k_Resp1kb_Iter1", [10000.0, 10000.0]),
        ("CommonThreatsWithDLP_SPS", "SxTest_AppMix_Mssf10k", [10000.0, 10000.0]),
    ]
)
def test_perf_cps_custom_tpp(
        sut_handle, datadir, ixia_handle,
        shieldx_constants, shieldx_logger,
        policy_name, traffic_profile, expected_cps):
    # SUT - System Under Test
    sut = SUT(sut_handle)

    # Traffic Gen
    breaking_point = BreakingPoint(ixia_handle)

    # Assign SPS to ACL (default)
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, policy_name)
    assert is_updated, "Assign the SPS under test."

    # Wait for the Policy to be updated, do with jobs to check when update is done
    time.sleep(20 * shieldx_constants["USER_WAIT"])

    # Check last completed job
    job = sut.get_last_completed_job()
    shieldx_logger.info("Job: {}".format(job))

    # Audit Log - Query log between start and end time
    # End time (ms) - now
    end_time = int(round(time.time()) * 1000)
    # Start time (ms) - 20 minutes ago
    start_time = end_time - (20 * 60000)

    # Get Audit Log - filter by action
    action = "Edit"
    audit_log_entries = sut.get_audit_log_by_action(start_time, end_time, action)
    shieldx_logger.info("Log count: {}".format(len(audit_log_entries)))
    for entry in audit_log_entries:
        shieldx_logger.info("Content Update Log: {}".format(entry))

    # Send traffic - get processed stats
    processed_stats = breaking_point.send_app_traffic(shieldx_constants["IXIA_SLOT"], shieldx_constants["IXIA_PORTS"], traffic_profile)

    # Debug - BP Info
    shieldx_logger.info("BP Model Name: {}".format(processed_stats["model_name"]))
    shieldx_logger.info("BP Test ID: {}".format(processed_stats["test_id"]))
    shieldx_logger.info("BP Test Iteration: {}".format(processed_stats["test_iteration"]))
    shieldx_logger.info("Avg Tx Tput: {}".format(processed_stats["avg_tx_tput"]))
    shieldx_logger.info("Avg Rx Tput: {}".format(processed_stats["avg_rx_tput"]))
    shieldx_logger.info("Avg TCP Client Establish Rate: {}".format(processed_stats["avg_tcp_client_established_rate"]))
    shieldx_logger.info("Avg TCP Server Establish Rate: {}".format(processed_stats["avg_tcp_server_established_rate"]))
    shieldx_logger.info("Avg TCP Resp Time: {}".format(processed_stats["avg_tcp_response_time"]))

    # Get the system info
    system_info = sut.get_system_info()

    # Reporting - ShieldX Info
    software_version = system_info["software_version"]
    content_version = system_info["content_version"]
    capacity = system_info["capacity"]
    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Debug - ShieldX Info
    shieldx_logger.info("Software: {}".format(software_version))
    shieldx_logger.info("Content: {}".format(content_version))
    shieldx_logger.info("Capacity: {}".format(capacity))
    shieldx_logger.info("SPS: {}".format(policy_name))

    # Reporting - BP Test Info
    test_model_id_iter = "{} - {} - {}".format(
        processed_stats["model_name"],
        processed_stats["test_iteration"],
        processed_stats["test_id"]
    )

    # Results - Repository
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_CPS_REPO"])

    # Results - Column Names
    column_names = [
        "Build", "Test Name - Iteration - Internal ID",
        "SPS", "Cpty",
        "AvgTxRate(Mbps)", "AvgRxRate(Mbps)",
        "AvgTCPClientCPS", "AvgTCPServerCPS",
        "AvgTCPResp(ms)"
    ]

    # Results - Column Widths
    column_widths = [26, 54, 24, 6, 16, 16, 16, 16, 16]

    # Results - Initialize
    shieldx_results = ResultsMgmt(result_dir, column_names, column_widths)

    # Results - Prep entry
    result = [
        build,
        test_model_id_iter,
        str(policy_name),
        capacity,
        processed_stats["avg_tx_tput"],
        processed_stats["avg_rx_tput"],
        processed_stats["avg_tcp_client_established_rate"],
        processed_stats["avg_tcp_server_established_rate"],
        processed_stats["avg_tcp_response_time"]
    ]

    # Results - Record entry
    shieldx_logger.info("Record result: {}".format(result))
    shieldx_results.add(result)

    # Cleanup below
    # Clear SPS from ACL Policy
    is_updated = False
    default_acl = "Default ACL Policy"
    is_updated = sut.assign_sps(default_acl, None)
    assert is_updated, "Cleanup, SPS set to none."

    # Pass/Fail Test

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_perf.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
