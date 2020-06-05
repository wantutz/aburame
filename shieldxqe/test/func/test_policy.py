import pytest

# shieldx library
from sxswagger.sxapi.policy_management import PolicyManagement as PolicyMgmt

@pytest.mark.policy_bats
def test_bats_000_get_access_control_policy(sut_handle, shieldx_logger):
    # Initialize
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Access Control Policy List
    access_control_policy_list = policy_mgmt.get_access_control_policy()

    for access_control_policy in access_control_policy_list:
        acp = dict(access_control_policy)

        if "id" in acp:
            shieldx_logger.info("Default Access Control ID: {}".format(acp["id"]))
        else:
            shieldx_logger.error("Default Access Control ID Not Found.")


# Sample run
#  python3 -m pytest shieldxqe/test/func/test_policy.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m policy_bats
#  python3 -m pytest shieldxqe/test/func/test_policy.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k access_control
