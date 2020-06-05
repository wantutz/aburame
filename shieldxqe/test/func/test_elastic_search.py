import pytest
import json

# shieldx library
from sxswagger.sxapi.elastic_search import ElasticSearch

@pytest.mark.skip(reason="No longer supported.")
def test_bats_000_nodes_info(sut_handle):
    es = ElasticSearch(sut_handle)

    # Get the nodes info
    nodes_info = es.get_nodes_info()

@pytest.mark.elastic_search_bats
def test_bats_000_multi_search(sut_handle, shieldx_logger):
    es = ElasticSearch(sut_handle)

    # ES Index
    index = "shieldxevents"

    # Check threat detection in the last 5 minutes
    # End time (ms) - now
    end_time = es.get_ms_timstamp()

    # Start time (ms) - 5 minutes ago
    start_time = end_time - (5 * 60000)

    # Query - payload is head + body
    head = get_index_payload(index)
    body = get_threat_detection_payload(start_time, end_time)
    payload = json.dumps(head) + "\n" + json.dumps(body)

    # Get the nodes info
    results = es.multi_search_query(payload)

    hits = results["responses"][0]["hits"]["hits"]
    for hit in hits:
        event = hit["_source"]["event"]
        shieldx_logger.info("Hit: {}:{}".format(event["pmId"], event["appId"]))

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
#  python3 -m pytest shieldxqe/test/func/test_elastic_search.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m elastic_search_bats
