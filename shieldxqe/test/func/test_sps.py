# Standard library
import json
import pytest

# shieldx library
from sxswagger.sxapi.policy_management import SecurityPolicySets as SPS_Mgmt
from sxswagger.sxapi.policy_management import ThreatPrevention as TPP_Mgmt

@pytest.mark.policy_bats
def test_bats_000_get_sps_list(sut_handle, shieldx_logger):
    policy_mgmt = SPS_Mgmt(sut_handle)

    canned_sps = ["Discover", "Testing", "All Inclusive"]

    # Get Security Policy Set
    sps_list = policy_mgmt.get_security_policy_set()

    for sps in sps_list:
        shieldx_logger.info("SPS Name: {}".format(sps["name"]))
        shieldx_logger.info("SPS ID: {}".format(sps["id"]))
        shieldx_logger.info("SPS: {}".format(sps))
        shieldx_logger.info("---\n")
        assert sps in sps_list, "SPS not in list."

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name", [
        "All Inclusive",
        "Discover",
        "Testing",
    ]
)
def test_bats_001_get_sps_by_name(sut_handle, shieldx_logger, policy_name):
    policy_mgmt = SPS_Mgmt(sut_handle)

    # Get Security Policy Set
    sps = policy_mgmt.get_sps_by_name(policy_name)

    sps_name = sps["name"]
    tpp_name = sps["threatPreventionPolicyName"]
    mp_name = sps["malwarePolicyName"]
    url_fp_name = sps["urlfilteringPolicyName"]

    shieldx_logger.info("SPS Name: {}".format(sps["name"]))
    shieldx_logger.info("SPS ID: {}".format(sps["id"]))
    shieldx_logger.info("SPS: {}".format(sps))
    shieldx_logger.info("---\n")

    assert policy_name == sps_name, "Unable to fetch the SPS by name."

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_id", [
        "3",
        "4",
        "5",
    ]
)
def test_bats_002_get_sps_by_id(sut_handle, shieldx_logger, policy_id):
    policy_mgmt = SPS_Mgmt(sut_handle)

    # Get Security Policy Set
    sps = policy_mgmt.get_sps_by_id(policy_id)

    sps_id = sps["id"]
    tpp_name = sps["threatPreventionPolicyName"]
    mp_name = sps["malwarePolicyName"]
    url_fp_name = sps["urlfilteringPolicyName"]

    shieldx_logger.info("SPS Name: {}".format(sps["name"]))
    shieldx_logger.info("SPS ID: {}".format(sps["id"]))
    shieldx_logger.info("SPS: {}".format(sps))
    shieldx_logger.info("---\n")

    assert int(policy_id) == int(sps_id), "Unable to fetch the SPS by ID."

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_id, policy_name, policy_components", [
        # Policy ID, Policy Name, Components: TPP, Malware Policy, and URL Filtering Policy
        ("3", "All Inclusive", ["All Threats", "WithSXCloud", "Default URL Filtering Policy"]),
        ("5", "Discover", ["AppVisibility", None, None]),
        ("4", "Testing", ["Common Threats", "WithSXCloud", None]),
    ]
)
def test_bats_001_check_sps_components(sut_handle, datadir, shieldx_logger,
        policy_id, policy_name, policy_components):
    policy_mgmt = SPS_Mgmt(sut_handle)

    # Get Security Policy Set
    sps = policy_mgmt.get_sps_by_id(policy_id)

    sps_name = sps["name"]
    tpp_name = sps["threatPreventionPolicyName"]
    mp_name = sps["malwarePolicyName"]
    url_fp_name = sps["urlfilteringPolicyName"]

    shieldx_logger.info("SPS Name: {}".format(sps_name))
    shieldx_logger.info("TPP Name: {}".format(tpp_name))
    shieldx_logger.info("MP Name: {}".format(mp_name))
    shieldx_logger.info("URL FP Name: {}".format(url_fp_name))
    shieldx_logger.info("SPS: {}".format(sps))

    # Check SPS Components
    # TPP
    assert tpp_name == policy_components[0]
    # Malware Policy
    assert mp_name == policy_components[1]
    # URL Filtering Policy
    assert url_fp_name == policy_components[2]

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name, policy_components", [
        # Policy Name, Components: TPP, Malware Policy, and URL Filtering Policy
        ("SxDatabase_SPS", ["sxDatabase", None, None]),
        ("SxLAMP_SPS", ["sxLAMP", None, None]),
        ("SxLEMP_SPS", ["sxLEMP", None, None]),
        ("SxMEAN_SPS", ["sxMEAN", None, None]),
        ("SxMSFTP_SPS", ["sxMSFTP", None, None]),
        ("SxNoSQLDatabase_SPS", ["sxNoSQLDatabase", None, None]),
        ("SxRDBMSDatabase_SPS", ["sxRDBMSDatabase", None, None]),
        ("SxTomcat_SPS", ["sxTomcat", None, None]),
        ("SxWAMP_SPS", ["sxWAMP", None, None]),
        ("SxWordPressLAMP_SPS", ["sxWordPressLAMP", None, None]),
        ("SxWordPressLEMP_SPS", ["sxWordPressLEMP", None, None]),
        ("SxLAMP_NOX_URL_SPS", ["sxLAMP", "WithSXCloud", "Default URL Filtering Policy"]),
        ("CommonThreatsWithDLP_SPS", ["CommonThreatsWithDLP", "WithSXCloud", None]),
    ]
)
def test_bats_002_create_sps(sut_handle, datadir, shieldx_logger,
        policy_name, policy_components):
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)

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

    # Populate the payload
    # Threat Prevention Policy
    tpp_name = policy_components[0]
    if tpp_name is not None:
        tpp = tpp_mgmt.get_threat_prevention_policy_by_name(tpp_name)
    else:
        tpp = None

    assert tpp is not None, "TPP not found, skipped SPS creation."
    shieldx_logger.info("TPP Name: {}".format(tpp["name"]))
    shieldx_logger.info("TPP ID: {}".format(tpp["id"]))

    # Malware Policy
    mp_name = policy_components[1]
    if mp_name == "WithSXCloud":
        # TODO: Fetch from API
        mp_id = 3
    else:
        mp_id = "null"

    # URL Filtering Policy
    ufp_name = policy_components[2]
    if ufp_name == "Default URL Filtering Policy":
        # TODO: Fetch from API
        ufp_id = 3
    else:
        ufp_id = "null"

    if create_payload is not None:
        # SPS Name
        create_payload["name"] = policy_name

        # Threat Prevention Policy
        create_payload["threatPreventionPolicyName"] = tpp_name
        create_payload["threatPreventionPolicyId"] = tpp["id"]

        # Malware Policy
        create_payload["malwarePolicyName"] = mp_name
        create_payload["malwarePolicyId"] = mp_id

        # URL Filtering Policy
        create_payload["urlfilteringPolicyName"] = ufp_name
        create_payload["urlfilteringPolicyId"] = ufp_id

        shieldx_logger.info("Create Payload: {}".format(create_payload))
        sps_id = sps_mgmt.create_security_policy_set(create_payload)

        assert sps_id != 0, "SPS creation failed, SPS ID returned is 0."
    else:
        assert False, "Skipped SPS creation."

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name, policy_components", [
        # Policy Name, Components: TPP, Malware Policy, and URL Filtering Policy
        ("SxDatabase_SPS", ["sxDatabase", None, None]),
        ("SxLAMP_SPS", ["sxLAMP", None, None]),
        ("SxLEMP_SPS", ["sxLEMP", None, None]),
        ("SxMEAN_SPS", ["sxMEAN", None, None]),
        ("SxMSFTP_SPS", ["sxMSFTP", None, None]),
        ("SxNoSQLDatabase_SPS", ["sxNoSQLDatabase", None, None]),
        ("SxRDBMSDatabase_SPS", ["sxRDBMSDatabase", None, None]),
        ("SxTomcat_SPS", ["sxTomcat", None, None]),
        ("SxWAMP_SPS", ["sxWAMP", None, None]),
        ("SxWordPressLAMP_SPS", ["sxWordPressLAMP", None, None]),
        ("SxWordPressLEMP_SPS", ["sxWordPressLEMP", None, None]),
        ("SxLAMP_NOX_URL_SPS", ["sxLAMP", "WithSXCloud", "Default URL Filtering Policy"]),
        ("CommonThreatsWithDLP_SPS", ["CommonThreatsWithDLP", "WithSXCloud", None]),
    ]
)
def test_bats_003_delete_sps(sut_handle, datadir, shieldx_logger,
        policy_name, policy_components):
    sps_mgmt = SPS_Mgmt(sut_handle)
    tpp_mgmt = TPP_Mgmt(sut_handle)

    sps = sps_mgmt.get_sps_by_name(policy_name)

    if sps is not None:
        sps_name = sps["name"]
        sps_id = sps["id"]

        shieldx_logger.info("Delete SPS Name: {}".format(sps_name))
        shieldx_logger.info("Delete SPS ID: {}".format(sps_id))

        is_deleted = sps_mgmt.delete_security_policy_set_by_id(sps_id)

        is_deleted == True, "SPS deletion failed."
    else:
        assert False, "SPS not found, delete skipped."

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_sps.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m policy_bats
