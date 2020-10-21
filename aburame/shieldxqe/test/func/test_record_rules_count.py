# standard library
import json
import pytest
import time

# shieldx - policy management
from sxswagger.sxapi.policy_management import ThreatPrevention as TPP_Mgmt

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - common
from sxswagger.common.custom_results import CustomResults as ResultsMgmt

@pytest.mark.content_bats
@pytest.mark.parametrize(
    "tpp_name", [
        # TPP Name
        ("All Threats"),
        ("AppVisibility"),
        ("Common Threats"),
        ("sxDatabase"),
        ("sxLAMP"),
        ("sxLEMP"),
        ("sxMEAN"),
        ("sxMSFTP"),
        ("sxNoSQLDatabase"),
        ("sxRDBMSDatabase"),
        ("sxScaleDemo"),
        ("sxTomcat"),
        ("sxWAMP"),
        ("sxWordPressLAMP"),
        ("sxWordPressLEMP"),
        ("xyZedLeppi"),
    ]
)
def test_count_tpp_rules(sut_handle, datadir, shieldx_constants, shieldx_logger, tpp_name):
    # Initialize
    # DUT
    tpp_mgmt = TPP_Mgmt(sut_handle)
    sys_mgmt = SysMgmt(sut_handle)

    # Get the system info
    system_info = sys_mgmt.get_system_info()
    software_version = system_info["version"]
    content_version = system_info["contentVersion"]

    # Results - ShieldX
    shieldx_logger.info("Software: {}".format(software_version))
    shieldx_logger.info("Content: {}".format(content_version))
    shieldx_logger.info("TPP: {}".format(tpp_name))

    # Save snapshots for reporting
    result_dir = "{}{}".format(shieldx_constants["SX_REPORT_REPO"], shieldx_constants["SX_TPP_RULES_REPO"])
    column_names = ["Build", "Threat Prevention Policy", "Threat Count", "App Count"]
    column_widths = [26, 24, 16, 16]

    build = "Mgmt{}Content{}".format(software_version, content_version)

    # Get Threat Prevention Policy
    tpp = tpp_mgmt.get_threat_prevention_policy_by_name(tpp_name)

    # Get rules - threats and apps
    if tpp is not None:
        # TPP ID
        tpp_id = tpp["id"]

        # Threats and Apps
        threats = tpp_mgmt.get_threats_by_policy_id(tpp_id)
        apps = tpp_mgmt.get_apps_by_policy_id(tpp_id)

        shieldx_logger.info("TPP Name: {}".format(tpp_name))
        shieldx_logger.info("TPP ID: {}".format(tpp_id))

        # Prep result
        shieldx_results = ResultsMgmt(result_dir, column_names, column_widths)
        result = [
            build,
            tpp_name,
            len(threats),
            len(apps)
        ]

        # Add result
        shieldx_results.add(result)
    else:
        shieldx_logger.error("Unable to find the  TPP.")

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_record_rules_count.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
