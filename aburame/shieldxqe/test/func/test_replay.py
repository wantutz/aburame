# Standard library
import pytest

# Functional Testing - Test Data provided by ThreatEncyclopedia class
from sxswagger.trafficgen.replaycenter import Replaycenter
from sxswagger.common.threat_encyclopedia import ThreatEncyclopedia as TE

@pytest.mark.content_test
@pytest.mark.parametrize("threat", TE.rules)
def test_func_001_pcap_replay(sut_handle, threat, shieldx_logger):
    replaycenter = Replaycenter(interface="eth0")

    replay_status = replaycenter.replay(threat)

    assert replay_status == replaycenter.codes.ok

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_replay.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m content_test
