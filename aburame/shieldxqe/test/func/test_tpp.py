# Standard library
import pytest
import json
import time

# shieldx library
from sxswagger.sxapi.policy_management import ThreatPrevention as PolicyMgmt
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

@pytest.mark.policy_bats
def test_bats_000_get_tpp_list(sut_handle, shieldx_logger):
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy List
    tpp_list = policy_mgmt.get_threat_prevention_policy_list()

    for tpp in tpp_list:
        shieldx_logger.info("TPP Name: {}".format(tpp["name"]))
        shieldx_logger.info("TPP ID: {}".format(tpp["id"]))
        shieldx_logger.info("---\n")

@pytest.mark.policy_bats
def test_bats_001_get_threats_by_policy(sut_handle, shieldx_logger):
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy List
    tpp_list = policy_mgmt.get_threat_prevention_policy_list()

    for tpp in tpp_list:
        # Get threats for each TPP
        threats = policy_mgmt.get_threats_by_policy_id(tpp["id"])

        shieldx_logger.info("TPP Name: {}".format(tpp["name"]))
        shieldx_logger.info("TPP ID: {}".format(tpp["id"]))
        shieldx_logger.info("Threat Count: {}".format(len(threats)))
        shieldx_logger.info("---\n")

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_id, policy_name", [
        (65536, "sxLAMP"),
        (65537, "sxWAMP"),
        (65538, "sxDatabase"),
        (65539, "sxScaleDemo"),
        (65540, "sxRDBMSDatabase"),
        (65541, "sxNoSQLDatabase"),
        (65542, "sxLEMP"),
        (65543, "sxWordPressLEMP"),
        (65544, "sxWordPressLAMP"),
        (65545, "sxMEAN"),
        (65546, "sxTomcat"),
        (65547, "sxMSFTP"),
        pytest.param(65548, "Negative Test TPP 1", marks=pytest.mark.xfail),
        (6, "AppVisibility"),
        pytest.param(5, "Negative Test TPP 2", marks=pytest.mark.xfail),
        (4, "Common Threats"),
        pytest.param(3, "Negative Test TPP 3", marks=pytest.mark.xfail),
        (2, "All Threats"),
        pytest.param(1, "Negative Test TPP 4", marks=pytest.mark.xfail),
    ]
)
def test_bats_002_get_tpp_by_policy_id(
    sut_handle,
    policy_id, policy_name,
    shieldx_constants, shieldx_logger
):
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy by ID
    tpp = policy_mgmt.get_threat_prevention_policy_by_id(policy_id)

    if tpp is not None:
        shieldx_logger.info("TPP Name: {}".format(tpp["name"]))
        shieldx_logger.info("TPP ID: {}".format(tpp["id"]))
        shieldx_logger.info("---\n")

        assert policy_name == tpp["name"], "TPP Name does not match."
        assert policy_id == tpp["id"], "TPP ID does not match."
    else:
        shieldx_logger.error("Unknown policy Name: {}".format(policy_name))
        shieldx_logger.error("Unknown policy ID: {}".format(policy_id))

    time.sleep(1 * shieldx_constants["USER_WAIT"])

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_id, policy_name", [
        (65536, "sxLAMP"),
        (65537, "sxWAMP"),
        (65538, "sxDatabase"),
        (65539, "sxScaleDemo"),
        (65540, "sxRDBMSDatabase"),
        (65541, "sxNoSQLDatabase"),
        (65542, "sxLEMP"),
        (65543, "sxWordPressLEMP"),
        (65544, "sxWordPressLAMP"),
        (65545, "sxMEAN"),
        (65546, "sxTomcat"),
        (65547, "sxMSFTP"),
        pytest.param(65548, "Negative Test TPP 1", marks=pytest.mark.xfail),
        (6, "AppVisibility"),
        pytest.param(5, "Negative Test TPP 2", marks=pytest.mark.xfail),
        (4, "Common Threats"),
        pytest.param(3, "Negative Test TPP 3", marks=pytest.mark.xfail),
        (2, "All Threats"),
        pytest.param(1, "Negative Test TPP 4", marks=pytest.mark.xfail),
    ]
)
def test_bats_003_get_tpp_by_policy_name(
    sut_handle,
    policy_id, policy_name,
    shieldx_constants, shieldx_logger
):
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy by Name
    tpp = policy_mgmt.get_threat_prevention_policy_by_name(policy_name)

    if tpp is not None:
        shieldx_logger.info("TPP Name: {}".format(tpp["name"]))
        shieldx_logger.info("TPP ID: {}".format(tpp["id"]))
        shieldx_logger.info("---\n")

        assert policy_name == tpp["name"], "TPP Name does not match."
        assert policy_id == tpp["id"], "TPP ID does not match."
    else:
        shieldx_logger.error("Unknown policy Name: {}".format(policy_name))
        shieldx_logger.error("Unknown policy ID: {}".format(policy_id))

    time.sleep(shieldx_constants["USER_WAIT"])

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name, clone_name, block_threats", [
        ("AppVisibility", "AppVisibility Clone", False),
        ("All Threats", "All Threats Blocked", True),
        ("Common Threats", "Common Threats Blocked", True),
        ("sxDatabase", "SxDatabase Clone", False),
        ("sxLAMP", "SxLAMP Clone", False),
        ("sxLEMP", "SxLEMP Clone", False),
        ("sxMEAN", "SxMEAN Clone", False),
        ("sxMSFTP", "SxMSFTP Clone", False),
        ("sxNoSQLDatabase", "SxNoSQLDatabase Clone", False),
        ("sxRDBMSDatabase", "SxRDBMSDatabase Clone", False),
        ("sxTomcat", "SxTomcat Clone", False),
        ("sxWAMP", "SxWAMP Clone", False),
        ("sxWordPressLAMP", "SxWordPressLAMP Clone", False),
        ("sxWordPressLEMP", "SxWordPressLEMP Clone", False),
    ]
)
def test_bats_011_clone_tpp(sut_handle, datadir, shieldx_logger,
    policy_name, clone_name, block_threats):
    """ Clone canned TPPs, block threats if flag is set. """
    from_policy_id = None
    to_policy_id = None

    threats = None
    apps = None

    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy
    tpp = policy_mgmt.get_threat_prevention_policy_by_name(policy_name)
    from_policy_id = tpp["id"]

    if from_policy_id is not None:
        threats = policy_mgmt.get_threats_by_policy_id(from_policy_id)
        apps = policy_mgmt.get_apps_by_policy_id(from_policy_id)
        shieldx_logger.info("TPP Name: {}".format(policy_name))
        shieldx_logger.info("TPP ID: {}".format(from_policy_id))
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
        clone_payload["name"] = clone_name
        clone_payload["tenantId"] = 1 # this should be fetched
        app_names = [app["name"] for app in apps]

        # Special handling based on the policy being cloned
        # Option is based on "Uses Specific Threats?" flag
        # This flag is based whether "specificThreats" is populated.
        if policy_name == "Common Threats" or policy_name == "AppVisibility":
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
    to_policy_id = policy_mgmt.create_threat_prevention_policy(clone_payload)
    shieldx_logger.info("Create OK, Policy ID: {}".format(to_policy_id))

    assert to_policy_id != 0, "TPP Clone failed."

    # Clone TPP responses
    is_cloned = policy_mgmt.clone_threat_prevention_policy_responses(
                  from_policy_id, to_policy_id)

    assert is_cloned == True, "Clone TPP responses failed."

    # Bulk Edit - Block threats
    if block_threats:
        threat_responses = policy_mgmt.get_threat_responses_by_policy_id(to_policy_id)
        for threat_response in threat_responses:
            #threat["alert"] = True
            threat_response["block"] = True
            #threat["enabled"] = True
            threat_response["policyId"] = to_policy_id

        response_payload["id"] = to_policy_id
        response_payload["responses"] = threat_responses

        shieldx_logger.info("Bulk Edit Payload: {}".format(response_payload))
        bulk_edit_success = policy_mgmt.bulk_update_threat_responses(response_payload)

        assert bulk_edit_success == True, "Bulk edit response action failed."
    else:
        pass

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name, clone_name, block_threats", [
        ("Common Threats", "CommonThreatsWithDLP", False),
    ]
)
def test_bats_012_clone_tpp_plus_dlp(sut_handle, datadir, shieldx_logger,
    policy_name, clone_name, block_threats):
    """ Clone canned TPPs; add DLP rules; block threats if flag is set. """
    from_policy_id = None
    to_policy_id = None

    threats = None
    apps = None

    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy
    tpp = policy_mgmt.get_threat_prevention_policy_by_name(policy_name)
    from_policy_id = tpp["id"]

    if from_policy_id is not None:
        threats = policy_mgmt.get_threats_by_policy_id(from_policy_id)
        apps = policy_mgmt.get_apps_by_policy_id(from_policy_id)
        shieldx_logger.info("TPP Name: {}".format(policy_name))
        shieldx_logger.info("TPP ID: {}".format(from_policy_id))
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
        clone_payload["name"] = clone_name
        clone_payload["tenantId"] = 1 # this should be fetched
        app_names = [app["name"] for app in apps]

        # Special handling based on the policy being cloned
        # Option is based on "Uses Specific Threats?" flag
        # This flag is based whether "specificThreats" is populated.
        if policy_name == "Common Threats" or policy_name == "AppVisibility":
            # no need to specify the "appNames" in the rules.
            # specify the "specificThreats" instead
            clone_payload["rules"] = [{"specificThreats": threats}, {"protocolNames": ["DLP"]}]
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
    to_policy_id = policy_mgmt.create_threat_prevention_policy(clone_payload)
    shieldx_logger.info("Create OK, Policy ID: {}".format(to_policy_id))

    assert to_policy_id != 0, "TPP Clone failed."

    # Clone TPP responses
    is_cloned = policy_mgmt.clone_threat_prevention_policy_responses(
                  from_policy_id, to_policy_id)

    assert is_cloned == True, "Clone TPP responses failed."

    # Bulk Edit - Block threats
    if block_threats:
        threat_responses = policy_mgmt.get_threat_responses_by_policy_id(to_policy_id)
        for threat_response in threat_responses:
            #threat["alert"] = True
            threat_response["block"] = True
            #threat["enabled"] = True
            threat_response["policyId"] = to_policy_id

        response_payload["id"] = to_policy_id
        response_payload["responses"] = threat_responses

        shieldx_logger.info("Bulk Edit Payload: {}".format(response_payload))
        bulk_edit_success = policy_mgmt.bulk_update_threat_responses(response_payload)

        assert bulk_edit_success == True, "Bulk edit response action failed."
    else:
        pass


@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name", [
        "All Threats Blocked",
        "AppVisibility Clone",
        "Common Threats Blocked",
        "SxDatabase Clone",
        "SxLAMP Clone",
        "SxLEMP Clone",
        "SxMEAN Clone",
        "SxMSFTP Clone",
        "SxNoSQLDatabase Clone",
        "SxRDBMSDatabase Clone",
        "SxTomcat Clone",
        "SxWAMP Clone",
        "SxWordPressLAMP Clone",
        "SxWordPressLEMP Clone",
        "CommonThreatsWithDLP",
    ]
)
def test_bats_013_delete_tpp(sut_handle, policy_name, shieldx_logger):
    is_deleted = False
    policy_id = None

    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy List
    tpp_list = policy_mgmt.get_threat_prevention_policy_list()

    for tpp in tpp_list:
        if policy_name == tpp["name"]:
            policy_id = tpp["id"]
            break
        else:
            continue

    if policy_id is not None:
        is_deleted = policy_mgmt.delete_threat_prevention_policy_by_id(policy_id)
    else:
        shieldx_logger.error("Unable to find the  TPP.")

    assert is_deleted == True, "Delete TPP failed."

@pytest.mark.policy_bats
def test_bats_021_get_content_attributes(sut_handle, shieldx_logger):
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Content Attributes
    content_attributes = policy_mgmt.get_content_attributes()

    shieldx_logger.info("Content Attribute Count: {}".format(len(content_attributes)))

    # Show sample
    shieldx_logger.info("Content Attribute Sample: {}".format(content_attributes[0]))
    shieldx_logger.info("Content Attribute Sample: {}".format(content_attributes[101]))
    shieldx_logger.info("Content Attribute Sample: {}".format(content_attributes[1001]))

@pytest.mark.policy_bats
def test_bats_022_get_protection_types(sut_handle, shieldx_logger):
    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Protection Types
    protection_types = policy_mgmt.get_protection_types()

    for protection_type in protection_types:
        shieldx_logger.info("Protection Type: {}".format(protection_type))

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "input_json_file, tpp_name, block_threats", [
        ("group1.json", "CreateByID_1_TPP", True),
    ]
)
def test_bats_023_tpp_by_rule_ids(sut_handle, datadir, shieldx_logger,
    input_json_file, tpp_name, block_threats):
    """ Create TPP by rule IDs, block threats if flag is set. """
    # Based on the All Threats TPP
    policy_name = "All Threats"

    from_policy_id = None
    to_policy_id = None

    threats = None
    apps = None

    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy
    tpp = policy_mgmt.get_threat_prevention_policy_by_name(policy_name)
    from_policy_id = tpp["id"]

    if from_policy_id is not None:
        threats = policy_mgmt.get_threats_by_policy_id(from_policy_id)
        apps = policy_mgmt.get_apps_by_policy_id(from_policy_id)
        shieldx_logger.info("TPP Name: {}".format(policy_name))
        shieldx_logger.info("TPP ID: {}".format(from_policy_id))
    else:
        shieldx_logger.error("Unable to find the  TPP.")

    # Selected Rule IDs
    resolved_input_json_file = str((datadir/input_json_file).resolve())
    selected_ids = list(read_config(resolved_input_json_file))
    #shieldx_logger.info("All Threat IDs: {}".format(threats))
    shieldx_logger.info("Selected IDs: {}".format(selected_ids))

    custom_threats = []
    for criteria in selected_ids:
        shieldx_logger.info("Criteria: {}".format(criteria))

        found_threat = search_threat(criteria, threats)

        if found_threat is not None:
            custom_threats.append(found_threat)
        else:
            pass

    shieldx_logger.info("Selected Threats: {}".format(custom_threats))

    # Fetch the payload from a config file
    tpp_config_file = "tpp.json"
    file_name = str((datadir/tpp_config_file).resolve())
    tpp_config = read_config(file_name)

    if tpp_config is not None:
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
        clone_payload["name"] = tpp_name
        clone_payload["tenantId"] = 1 # this should be fetched
        clone_payload["rules"] = [{"specificThreats": custom_threats}]
    else:
        shieldx_logger.error("Unable to fetch the TPP payload from config file.")

    # Create a clone of a TPP, get the TPP ID back
    to_policy_id = policy_mgmt.create_threat_prevention_policy(clone_payload)
    shieldx_logger.info("Create OK, Policy ID: {}".format(to_policy_id))

    assert to_policy_id != 0, "TPP Clone failed."

    # Bulk Edit - Block threats
    if block_threats:
        threat_responses = policy_mgmt.get_threat_responses_by_policy_id(to_policy_id)
        for threat_response in threat_responses:
            threat_response["block"] = True
            threat_response["policyId"] = to_policy_id

        response_payload["id"] = to_policy_id
        response_payload["responses"] = threat_responses

        shieldx_logger.info("Bulk Edit Payload: {}".format(response_payload))
        bulk_edit_success = policy_mgmt.bulk_update_threat_responses(response_payload)

        assert bulk_edit_success == True, "Bulk edit response action failed."
    else:
        pass

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name", [
        "CreateByID_1_TPP",
        "CreateByID_2_TPP",
        "CreateByID_3_TPP",
    ]
)
def test_bats_024_delete_tpp(sut_handle, policy_name, shieldx_logger):
    is_deleted = False
    policy_id = None

    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy List
    tpp_list = policy_mgmt.get_threat_prevention_policy_list()

    for tpp in tpp_list:
        if policy_name == tpp["name"]:
            policy_id = tpp["id"]
            break
        else:
            continue

    if policy_id is not None:
        is_deleted = policy_mgmt.delete_threat_prevention_policy_by_id(policy_id)
        assert is_deleted == True, "Delete TPP failed."
    else:
        shieldx_logger.error("NOOP - Unable to find the  TPP.")


@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "input_json_file, tpp_name, block_threats", [
        ("group10.json", "CreateByName_1_TPP", False),
        ("group11.json", "CreateByName_2_TPP", True),
    ]
)
def test_bats_025_tpp_by_rule_ids(sut_handle, datadir, shieldx_logger,
    input_json_file, tpp_name, block_threats):
    """ Create TPP by rule IDs, block threats if flag is set. """
    # JSON Config Reader
    config_reader = CCR()

    # Based on the All Threats TPP
    policy_name = "All Threats"

    from_policy_id = None
    to_policy_id = None

    threats = None
    apps = None

    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy
    tpp = policy_mgmt.get_threat_prevention_policy_by_name(policy_name)
    from_policy_id = tpp["id"]

    if from_policy_id is not None:
        threats = policy_mgmt.get_threats_by_policy_id(from_policy_id)
        apps = policy_mgmt.get_apps_by_policy_id(from_policy_id)
        shieldx_logger.info("TPP Name: {}".format(policy_name))
        shieldx_logger.info("TPP ID: {}".format(from_policy_id))
    else:
        shieldx_logger.error("Unable to find the  TPP.")

    # Selected Rule IDs
    resolved_input_json_file = str((datadir/input_json_file).resolve())
    selected_app_names = list(config_reader.read_json_config(resolved_input_json_file))
    shieldx_logger.info("Selected Names: {}".format(selected_app_names))

    # Fetch the payload from a config file
    tpp_config_file = "tpp.json"
    resolved_tpp_config_file = str((datadir/tpp_config_file).resolve())
    tpp_config = read_config(resolved_tpp_config_file)

    if tpp_config is not None:
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
        clone_payload["name"] = tpp_name
        clone_payload["tenantId"] = 1 # this should be fetched
        clone_payload["rules"] = [{"appNames": selected_app_names}]
    else:
        shieldx_logger.error("Unable to fetch the TPP payload from config file.")

    # Create a clone of a TPP, get the TPP ID back
    to_policy_id = policy_mgmt.create_threat_prevention_policy(clone_payload)
    shieldx_logger.info("Create OK, Policy ID: {}".format(to_policy_id))

    assert to_policy_id != 0, "TPP Clone failed."

    # Bulk Edit - Block threats
    if block_threats:
        threat_responses = policy_mgmt.get_threat_responses_by_policy_id(to_policy_id)

        if len(threat_responses) > 0:
            for threat_response in threat_responses:
                threat_response["block"] = True
                threat_response["policyId"] = to_policy_id

            response_payload["id"] = to_policy_id
            response_payload["responses"] = threat_responses

            shieldx_logger.info("Bulk Edit Payload: {}".format(response_payload))
            bulk_edit_success = policy_mgmt.bulk_update_threat_responses(response_payload)

            assert bulk_edit_success == True, "Bulk edit response action failed."
        else:
            shieldx_logger.error("NOOP - no threat found.")
    else:
        shieldx_logger.info("NOOP - no blocking required.")

@pytest.mark.policy_bats
@pytest.mark.parametrize(
    "policy_name", [
        "CreateByName_1_TPP",
        "CreateByName_2_TPP",
        "CreateByName_2_TPP",
    ]
)
def test_bats_026_delete_tpp(sut_handle, policy_name, shieldx_logger):
    is_deleted = False
    policy_id = None

    policy_mgmt = PolicyMgmt(sut_handle)

    # Get Threat Prevention Policy List
    tpp_list = policy_mgmt.get_threat_prevention_policy_list()

    for tpp in tpp_list:
        if policy_name == tpp["name"]:
            policy_id = tpp["id"]
            break
        else:
            continue

    if policy_id is not None:
        is_deleted = policy_mgmt.delete_threat_prevention_policy_by_id(policy_id)
        assert is_deleted == True, "Delete TPP failed."
    else:
        shieldx_logger.error("NOOP - Unable to find the  TPP.")


# Functional Testing - Test Data provided by ThreatEncyclopedia class
from sxswagger.common.threat_encyclopedia import ThreatEncyclopedia as TE

@pytest.mark.policy_threat
@pytest.mark.parametrize("threat", TE.rules)
def test_func_001_check_threat_encyclopedia_references(sut_handle, threat, shieldx_logger):
    policy = PolicyMgmt(sut_handle)

    try:
        # Get existing threat prevention policies
        threat_info = policy.get_threat_encyclopedia(threat["pm_id"], threat["rule_id"])

        shieldx_logger.info("Threat Info: {}".format(threat_info))
        assert threat_info["entries"]["name"] == threat["name"], "Name mismatch."
    except Exception as e:
        shieldx_logger.error(e)

@pytest.mark.policy_threat
def test_func_002_check_threat_severities(sut_handle, shieldx_logger):
    policy = PolicyMgmt(sut_handle)

    expected_severities = ["Critical", "High", "Medium", "Low"].sort()

    try:
        # Get threat severities
        threat_severities = policy.get_threat_severities()

        shieldx_logger.info("Threat Severities: {}".format(threat_severities))
        assert threat_severities.sort() == expected_severities, "Threat Severity mismatch."
    except Exception as e:
        shieldx_logger.error(e)

# Helper functions
def read_config(json_file):
    json_config = None

    with open(json_file, 'r') as config_file:
        json_config = json.load(config_file)

    return json_config

def search_threat(criteria, list_of_threats):
    found_threat = None

    for threat in list_of_threats:
        #print("Threat: {}".format(threat))

        #print("Criteria Protocol ID: {}".format(criteria["protocolID"]))
        #print("Threat Protocol ID: {}".format(threat["protocolID"]))
        #print("Criteria Threat ID: {}".format(criteria["threatID"]))
        #print("Threat Threat ID: {}".format(threat["threatID"]))

        if int(criteria["protocolID"]) == int(threat["protocolID"]) and \
           int(criteria["threatID"]) == int(threat["threatID"]):
            found_threat = threat
            print("Found Threat: {}".format(threat))
        else:
            pass

    return found_threat

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_tpp.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m policy_bats
