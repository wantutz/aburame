#!/bin/bash

# Host where script will run
test_manager=172.16.27.110

# Target UM, and account info
um=172.16.27.73
user=sxapi
pass=Admin@123

# DevOps License
license=<devops license>

# Connect to Test Manager
ssh -l root $test_manager <<END

# Activate Virtual Environment
source /root/abu_env/bin/activate

# Go to Automation directory
cd /root/ShieldX/Automation

# Check the patterns for each test QE can run individual tests
python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --um $um --username $user --password $pass --collect-only


if [[ $PRE_TEST_CLEANUP = true ]]; then
    echo "Cleanup obsolete policies before running tests."

    # Cleanup before test - occasionally, clean up from previous test round
    python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --um $um --username $user --password $pass -k test_del_setup
else
    echo "Pre Test - no cleanup - reuse existing policies"
fi


if [[ $UPDATE_CONTENT = true ]]; then
    echo "Update to latest content before running tests."

    # Initialization
    python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --license $license --um $um --username $user --password $pass -k test_init_setup
else
    echo "Use existing content, and existing TPP and SPS."
fi


if [[ $RUN_BP_TEST = true ]]; then
    echo "Run BP Traffic - Exploits Strikes Test"

    # Strikes Test
    python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --um $um --username $user --password $pass -k test_strikes_by_year_and_direction

    # Debug - single tests
    # BATS
    #python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --um $um --username $user --password $pass -k test_strikes_by_year_and_direction[SxSecurityTest_BATS-100]
    #python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --um $um --username $user --password $pass -k test_strikes_by_year_and_direction[SxSecurityTest_NoSSL_Content2_1_45-100]
    #python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --um $um --username $user --password $pass -k test_strikes_by_year_and_direction[SxSecurityTest_NoSSL_Content2_1_48-100]
else
    echo "No traffic."
fi

if [[ $POST_TEST_CLEANUP = true ]]; then
    echo "Cleanup created TPP and SPS policies"

    # Cleanup after test - sometimes, don't do cleanup
    #python3 -m pytest shieldxqe/test/func/test_strikes.py -v --setup-show -s --um $um --username $user --password $pass -k test_del_setup
else
    echo "Post Test - no cleanup to allow debugging."
fi

# Deactivate Virtual Environment
deactivate

# Test END
END
