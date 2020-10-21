# standard library
import pytest
import time
import json

# shieldx - system under test
from sxswagger.sxapi.system_under_test import SystemUnderTest as SUT

# shieldx - elastic search
from sxswagger.sxapi.elastic_search import ElasticSearch as ES

# shieldx - logs management
from sxswagger.sxapi.audit_log import AuditLog as AL

# shieldx - common

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "acl_container, security_policy_set", [
        ("Default ACL Policy", "All Inclusive"),
        ("Default ACL Policy", "Discover"),
        ("Default ACL Policy", "Testing"),
    ]
)
def test_access_control_sps(
    sut_handle,
    shieldx_constants,
    shieldx_logger,
    acl_container,
    security_policy_set
):
    # Initialize
    sut = SUT(sut_handle)
    es_mgmt = ES(sut_handle)
    audit_log_mgmt = AL(sut_handle)
    active_sps = None

    try:
        active_sps = sut.get_sps(acl_container)
        shieldx_logger.info("Active SPS: {}".format(active_sps))
    except AttributeError as e:
        shieldx_logger.error(e)
        shieldx_logger.info("Active SPS: None")

    if active_sps == security_policy_set:
        # NOOP
        shieldx_logger.info("NOOP, requested SPS is currently active.")
    else:
        # Start time (ms)
        start_time = es_mgmt.get_ms_timstamp()

        # Assign SPS to ACL Container
        is_updated = False
        is_updated = sut.assign_sps(acl_container, security_policy_set)
        assert is_updated, "Assign the SPS to the given ACL Container."

        # Policy set estimated time
        time.sleep(20 * shieldx_constants["USER_WAIT"])

        # End time (ms)
        end_time = es_mgmt.get_ms_timstamp()

        # Craft query
        query = json.dumps({
            "eventType": "AUDIT_LOG",
            "gte": start_time,
            "lte": end_time,
            "queryType": "TABLE",
            "size": 100
        })

        # Check Audit Log
        audit_log_entries = audit_log_mgmt.get_audit_log(query=query)
        shieldx_logger.debug("Log: {}".format(audit_log_entries))
        shieldx_logger.info("Log count: {}".format(len(audit_log_entries)))

        # Filter by component type
        component_type = "Access Control Policy"
        filtered_logs = [entry for entry in audit_log_entries if "componentType" in entry.get("log", {})]
        for entry in filtered_logs:
            if component_type in entry["log"]["componentType"]:
                shieldx_logger.info("ACL Change Log: {}".format(entry))
            else:
                pass

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_sut.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
