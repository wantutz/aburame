import pytest

# shieldx library
from sxswagger.sxapi.access_control_policy import AccessControl as ACL
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

@pytest.mark.policy_bats
def test_bats_000_get_access_control_policy(sut_handle, shieldx_logger):
    # Initialize
    acl_mgmt = ACL(sut_handle)

    # Get Access Control Policy List
    access_control_policy_list = acl_mgmt.get_acl_policies()

    for access_control_policy in access_control_policy_list:
        acp = dict(access_control_policy)

        if "id" in acp:
            shieldx_logger.info("Default Access Control ID: {}".format(acp["id"]))
            shieldx_logger.info(acp)
        else:
            shieldx_logger.error("Default Access Control ID Not Found.")

@pytest.mark.policy_bats
def test_bats_001_get_acl_rules(sut_handle, shieldx_logger):
    # Initialize
    acl_mgmt = ACL(sut_handle)

    # Get Access Control Policy List
    access_control_policy_list = acl_mgmt.get_acl_policies()

    for access_control_policy in access_control_policy_list:
        acp = dict(access_control_policy)

        for rule in acp["aclRules"]:
            shieldx_logger.info("ACL Rule: {}".format(rule))

@pytest.mark.parametrize(
    "config_file", [
        "acl_rule1.json",
    ]
)
@pytest.mark.policy_bats
def test_bats_002_add_acl_rule(sut_handle, datadir, config_file, shieldx_logger):
    # Initialize
    acl_mgmt = ACL(sut_handle)

    # JSON Config Reader
    config_reader = CCR()

    # Selected Rule IDs
    resolved_input_json_file = str((datadir/config_file).resolve())
    acl_config = config_reader.read_json_config(resolved_input_json_file)

    # Get Default Access Control Policy
    default_access_control_policy = acl_mgmt.get_acl_policies()[0]

    shieldx_logger.info("Before Add - Default ACP: {}".format(default_access_control_policy))

    # Clone ACL Rule and modify relevant fields
    new_acl_rule = default_access_control_policy["aclRules"][0].copy()
    del(new_acl_rule["id"])
    new_acl_rule["name"] = acl_config["acl_rule1"]["name"]
    new_acl_rule["description"] = acl_config["acl_rule1"]["description"]

    # TODO
    # new_acl_rule["spsId"] = (compute from vitual patch SPS ID)
    # new_acl_rule["sourceResourceGroupList"] = (compute from RG or NS created based on WL IP from vuln scanner)
    # new_acl_rule["destinationResourceGroupList"] = (compute from RG or NS created based on WL IP from vuln scanner)

    # Append the new rule
    default_access_control_policy["aclRules"].append(new_acl_rule)

    # Fix order number, newly created rule is #1
    acl_rules_count = len(default_access_control_policy["aclRules"])

    for acl_rule in default_access_control_policy["aclRules"]:
        acl_rule["orderNum"] = acl_rules_count
        acl_rules_count -= 1

    shieldx_logger.info("After Add - Default ACP: {}".format(default_access_control_policy))

    is_updated = acl_mgmt.update_acl(default_access_control_policy)

    shieldx_logger.info("ACL Update status: {}".format(is_updated))

@pytest.mark.parametrize(
    "config_file", [
        "acl_rule1.json",
    ]
)
@pytest.mark.policy_bats
def test_bats_003_del_acl_rule(sut_handle, datadir, config_file, shieldx_logger):
    # Initialize
    acl_mgmt = ACL(sut_handle)

    # JSON Config Reader
    config_reader = CCR()

    # Selected Rule IDs
    resolved_input_json_file = str((datadir/config_file).resolve())
    acl_config = config_reader.read_json_config(resolved_input_json_file)

    # Get Default Access Control Policy
    default_access_control_policy = acl_mgmt.get_acl_policies()[0]

    shieldx_logger.info("Before Del - Default ACP: {}".format(default_access_control_policy))

    # Delete ACL Rule
    index = 0
    for acl_rule in default_access_control_policy["aclRules"]:
        if acl_rule["name"] == acl_config["acl_rule1"]["name"]:
            # Pop based on index
            _ = default_access_control_policy["aclRules"].pop(index)
            break

        index += 1

    shieldx_logger.info("After Del - Default ACP: {}".format(default_access_control_policy))

    is_updated = acl_mgmt.update_acl(default_access_control_policy)

    shieldx_logger.info("ACL Update status: {}".format(is_updated))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_access_control.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m policy_bats
