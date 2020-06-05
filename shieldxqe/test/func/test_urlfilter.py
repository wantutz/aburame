import pytest

# shieldx library
from sxswagger.sxapi.policy_management import PolicyManagement as PolicyMgmt

@pytest.mark.policy_bats
def test_bats_000_get_tpp_list(sut_handle, shieldx_logger):
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get URL Filtering Policy List
    url_policy_list = policy_mgmt.get_url_filtering_policy()

    shieldx_logger.info("URL Policy: {}".format(url_policy_list))

    for url_policy in url_policy_list:
        shieldx_logger.info("URL Policy Name: {}".format(url_policy["name"]))
        shieldx_logger.info("URL Policy ID: {}".format(url_policy["id"]))
        shieldx_logger.info("---\n")

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_urlfilter.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m policy_bats
