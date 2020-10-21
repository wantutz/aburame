import pytest
import requests
import sys
import time

from os import path

# shieldx library
from sxswagger.sxapi.sx_demo import SxDemo

@pytest.mark.demo
def test_demo_0001_get_capacity(sut_handle):
    demo = SxDemo(sut_handle)

    capacity1 = demo.get_capacity1()
    print("Capacity1: ", capacity1)

    capacity2 = demo.get_capacity2()
    print("Capacity2: ", capacity2)

    capacity3 = demo.get_capacity3()
    print("Capacity3: ", capacity3)

    assert "2Gb" in capacity1, "Unexpected capacity"
    assert "2Gb" in capacity2, "Unexpected capacity"
    assert "2Gb" in capacity3, "Unexpected capacity"

@pytest.mark.demo
def test_demo_0002_pytestconfig(pytestconfig):
    """ Sample test to use command line options. """
    print("\n---")
    print("Branch: ", pytestconfig.getoption('branch'))
    print("ShieldX Flag: ", pytestconfig.getoption('shieldx'))

@pytest.mark.demo
def test_demo_0003_tmpdir_factory(tmpdir_factory):
    """ Sample test to showcase tmpdir_factory. """
    print("\n---")
    print("Base Temp Dir: ", tmpdir_factory.getbasetemp())

@pytest.mark.demo
def test_demo_0004_datadir(datadir):
    """ Sample test to use datadir. """
    with (datadir/'sample.txt').open() as file_handle:
        for line in file_handle:
            assert "ip" in line, "IP sample not found."

@pytest.mark.demo
def test_demo_0005_ixia_handle(ixia_handle):
    """ Sample test to use ixia connection. """
    print("Ixia Cookie: {}".format(ixia_handle.cookie))

@pytest.mark.demo
@pytest.mark.parametrize("index", [1, 2, 3])
@pytest.mark.parametrize("names", ["ghirard", "belli", "didi"])
def test_demo_0006_stacked_parameter(index, names, shieldx_logger):
    """ Stacking Parameters """
    shieldx_logger.info("{} - {}".format(index, names))

@pytest.mark.demo
@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize("names", ["geralt", "yennefer", "ciri"])
def test_demo_0007_stacked_parameter(index, names, shieldx_logger):
    """ Stacking Parameters """
    shieldx_logger.info("{} - {}".format(index, names))


@pytest.mark.demo
def test_demo_0008_generate_tests(stringinput):
    """ Use generated tests """
    assert stringinput.isalpha()

# Sample run
# Run specific file
#  py.test test_demo.py
#  python3 -m pytest shieldxqe/test/func/test_demo.py

# Search for tests, match pattern = capacity
#  py.test test_demo.py -k capacity

# Search for tests, use mark = suite1
#  py.test test_demo.py -m suite1
#  python3 -m pytest shieldxqe/test/func/test_demo.py -m suite1

# Verbose and setup logs shown
#  python3 -m pytest shieldxqe/test/func/test_demo.py -v --setup-show

# Show system info; -s will show print output
#  python3 -m pytest shieldxqe/test/func/test_demo.py -v --setup-show -s

# Show system info; -s will show print output
#  python3 -m pytest shieldxqe/test/func/test_demo.py -v --setup-show -s --shieldx --branch SxRel2.1
