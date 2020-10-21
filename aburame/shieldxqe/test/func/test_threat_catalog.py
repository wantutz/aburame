# Standard library
import pytest

# shieldx library
from sxswagger.sxapi.policy_management import ThreatPrevention as PolicyMgmt
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR

@pytest.mark.policy_threat
@pytest.mark.parametrize("threat_json", [
        "Content2.1.45.json",
        "Content2.1.48.json",
        "Content2.1.51.json",
        "Content2.1.53.json",
        "Content2.1.55.json",
        "Content2.1.59.json",
        "Content2.1.62.json",
        "Content2.1.65.json",
        "Content2.1.69.json",
        "Content2.1.71.json",
        "Content2.1.73.json",
        "Content2.1.75.json",
    ]
)
def test_threat_catalog_by_rev_history(
    sut_handle,
    datadir, threat_json,
    shieldx_logger
):
    # JSON Config Reader
    config_reader = CCR()
    # Policy Manager
    policy = PolicyMgmt(sut_handle)

    # Selected Rule IDs
    resolved_input_json_file = str((datadir/threat_json).resolve())
    threats = list(config_reader.read_json_config(resolved_input_json_file))
    shieldx_logger.info("Threats : {}".format(threats))

    for threat in threats:
        # Get threat info from catalog
        threat_info = policy.get_threat_encyclopedia(threat["pm_id"], threat["rule_id"])
        shieldx_logger.info("Threat Info: {}".format(threat_info))

        if threat_info["entries"] is not None:
            shieldx_logger.info("Threat Info - Entries: {}".format(threat_info["entries"]))
        else:
            shieldx_logger.error("Threat Info not found for: {}".format(threat))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_threat_catalog.py -v --setup-show -s --um <umip> --username <user> --password <passwd>
