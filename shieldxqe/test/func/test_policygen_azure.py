import pytest
from sxswagger.common.testrail import *

# shieldx - sxapi library
from sxswagger.sxapi.policy_gen import PolicyGen

client = APIClient('https://testrail.shieldx.local/testrail/')
client.user = 'surbhi@shieldx.com'
client.password = '9HbjJYWwktrylKI-7DwAzZ1Hmh3gnyDN.LZp'

@pytest.mark.policygen_regress
def test_000_get_acl_connects(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.get_acl_connections()
    total = 0
    for i in status:
        total += i["newACLsCount"]
    print("ACL connections seen are %s" % total)
    assert total > 0, "PolicyGen is running and seeing ACL connections"

@pytest.mark.policygen_regress
def test_001_start_forward_testing(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status,time= policygen1.start_forward_testing()
    time_started = time
    assert status == 200, "Forward testing has been started on policygen"

@pytest.mark.policygen_regress
def test_002_get_forward_testing_time(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    forward_tt, time = policygen1.get_forward_testing_time()
    print("Policy Gen started forward testing at",forward_tt)
    assert time, "Forward testing has been started on policygen"

@pytest.mark.policygen_regress
def test_003_implement_all_commonservices(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.implement_all_commonservices()
    print("Implement all common services has completed successfully")
    if status ==200:
        result = client.send_post(
            'add_result/12281',
            {'status_id': 1, 'comment': 'Marked using automation'}
        )
        print(result)
        assert status == 200, "Implement all common services has completed "
    else:
        result = client.send_post(
            'add_result/12281',
            {'status_id': 5, 'comment': 'Marked using automation - Failed to purge data %s' % status}
        )
        print(status)
        assert False

@pytest.mark.policygen_regress
def test_004_purge_data(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.purge_data_gm()
    print("Data has been purged")
    if status ==200:
        result = client.send_post(
            'add_result/12371',
            {'status_id': 1, 'comment': 'Marked using automation'}
        )
        result = client.send_post(
            'add_result/12307',
            {'status_id': 1, 'comment': 'Marked using automation'}
        )
        print(result)
        assert status == 200, "Purge completed successfully "
    else:

        result = client.send_post(
            'add_result/12371',
            {'status_id': 5, 'comment': 'Marked using automation - Failed to purge data %s' % status}
        )
        print(result)

@pytest.mark.policygen_regress
def test_005_implement_all_applications(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.implement_all_apps()
    print("Implement all applications completed successfully")
    if status ==200:
        result = client.send_post(
            'add_result/12395',
            {'status_id': 1, 'comment': 'Marked using automation'}
        )
        print(result)
        assert status == 200, "Implement all applications has completed "
    else:
        result = client.send_post(
            'add_result/12395',
            {'status_id': 5, 'comment': 'Marked using automation'}
        )
        print(status)
        assert False

@pytest.mark.policygen_regress
def test_006_summary_details(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    appsummary = policygen1.app_summary()
    print(appsummary)
    print("Summary of Apps")
    if appsummary:
        result = client.send_post(
            'add_result/12380',
            {'status_id': 1, 'comment': 'Marked using automation %s ' % appsummary}
        )
        print(result)
        assert True
    else:
        result = client.send_post(
            'add_result/12380',
            {'status_id': 5, 'comment': 'Marked using automation'}
        )
        assert False

@pytest.mark.policygen_regress
def test_007_delete_all_apps(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.delete_all()
    if status == 200:
        result = client.send_post(
            'add_result/12396',
            {'status_id': 1, 'comment': 'Marked using automation '}
        )
        print(result)
        assert status == 200, ""
    else:
        result = client.send_post(
            'add_result/12396',
            {'status_id': 5, 'comment': 'Marked using automation'}
        )
        assert False


@pytest.mark.policygen_regress
def test_008_get_network_sets(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status,networksetlisting = policygen1.get_network_sets()
    if status == 200:
        print (networksetlisting)
        assert status == 200, ""
    else:
        assert False

@pytest.mark.policygen_regress
def test_009_set_filter_config(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.set_filter_config()
    if status == 200:
        assert status == 200, "Filters have been set and GM processing has started"
    else:
        assert False

@pytest.mark.policygen_regress
def test_010_enforce_policy_deny(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.set_deny_policy()
    if status == 200:
        assert status == 200, "Enforced DENY Policy"
    else:
        assert False

@pytest.mark.policygen_regress
def test_010_enforce_policy_permit(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.set_permit_policy()
    if status == 200:
        assert status == 200, "Enforced DENY Policy"
    else:
        assert False

@pytest.mark.policygen_regress
def test_011_implement_individual_applications(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.implement_individual_applications()
    if status == 200:
        assert status == 200, "Apps are implemented"
    else:
        assert False

@pytest.mark.policygen_regress
def test_012_get_violations(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status,violations = policygen1.get_violations()
    if status == 200:
        print(violations)
        if violations == []:
            print("There are no violations in the system currently")
        assert status == 200, "Violations are able to get fetched"
    else:
        assert False

@pytest.mark.policygen_regress
def test_013_implement_all_violations(sut_handle):
    policygen1 = PolicyGen(sut_handle)
    status = policygen1.add_all_violations_aclPolicy()
    if status == 200:
        assert status == 200, "All violations are added to the ACL Policy"
    else:
        assert False

@pytest.mark.parametrize("export_file",
                         ["policygen_flowlogs.yaml"])
@pytest.mark.policygen_regress
def test_013_setup_flow_logs(sut_handle,datadir,export_file):
    policygen1 = PolicyGen(sut_handle)
    file_name = str(datadir/export_file)
    status = policygen1.set_flow_logs(file_name)
    print(status)
    if status == 200:
        assert status == 200, ""
    else:
        assert False








