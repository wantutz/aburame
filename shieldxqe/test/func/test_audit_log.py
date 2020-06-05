# standard library
import json
import pytest
import time

# shieldx - logs management
from sxswagger.sxapi.audit_log import AuditLog

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - elastic search
from sxswagger.sxapi.elastic_search import ElasticSearch as ES

@pytest.mark.demo
def test_get_log(
    sut_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    es_mgmt = ES(sut_handle)
    audit_log_mgmt = AuditLog(sut_handle)

    # End time (ms) - now
    end_time = es_mgmt.get_ms_timstamp()

    # Start time (ms) - 15 minutes ago
    start_time = end_time - (15 * 60000)

    # Craft query
    query = json.dumps({
        "eventType": "AUDIT_LOG",
        "gte": start_time,
        "lte": end_time,
        "queryType": "TABLE",
        "size": 100
    })

    # Get Audit Log
    audit_log_entries = audit_log_mgmt.get_audit_log(query=query)
    shieldx_logger.info("Log count: {}".format(len(audit_log_entries)))

    # Filter by action - login
    action = "Login"
    filtered_logs = [entry for entry in audit_log_entries if action in entry["log"]["action"]]
    for entry in filtered_logs:
        shieldx_logger.info("Auth Log: {}".format(entry))

    # Filter by action - content update
    action = "Content Update"
    filtered_logs = [entry for entry in audit_log_entries if action in entry["log"]["action"]]
    for entry in filtered_logs:
        shieldx_logger.info("Content Update Log: {}".format(entry))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_audit_log.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
