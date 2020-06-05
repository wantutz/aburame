# standard library
import pytest
import importlib

def pytest_generate_tests(metafunc):
    """ This allows us to load tests from external files by
    parametrizing tests with each test case found in data_X
    file """

    for fixture in metafunc.fixturenames:
        if fixture.startswith("data_"):
            # Load associated  test data
            tests = load_tests(fixture)
            metafunc.parametrize(fixture, tests)

def load_tests(name):
    # Load module that contains test data
    tests_module = importlib.import_module(name)

    # Tests are found in the variable "tests" of the module
    for test in tests_module.tests.iteritems():
        yield test

def test_feature(.data_hooks):
    assert data_hooks < 9, "Input number is not less than 9."

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_hooks.py
