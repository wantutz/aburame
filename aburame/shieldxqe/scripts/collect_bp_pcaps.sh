#!/bin/bash

# Host where script will run
test_manager=172.16.27.110

# Connect to Test Manager
ssh -l root $test_manager <<END

# Activate Virtual Environment
source /root/bp_pcap3/bin/activate

# Go to Automation directory
cd /root/ShieldX/Automation/Features/ixia_bp_collect_pcap

# Collect Pcaps
./bpsh-linux-x86-351814 custom_strike_pcap_gen.tcl

# Deactivate Virtual Environment
deactivate

# Test END
END
