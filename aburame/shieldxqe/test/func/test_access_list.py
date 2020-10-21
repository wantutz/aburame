import pytest
import requests
import sys
import time

# shieldx library
from sxswagger.sxapi.acl_policy import AccessControl
from sxswagger.sxapi.jobs_apis import JobsApis
from sxswagger.sxapi.dataplane_management import DataplaneManagement
from sxswagger.sxapi.group_insert import GroupandInsert

@pytest.mark.acl_policy_bats
def test_bats_000_acl_policy_commonsetup_insertion(sut_handle):

    group_handle = GroupandInsert(sut_handle)
    nsid_1 = group_handle.nset_create_noinsertion(rname = "NSET-1-tonydev", regexpr = "ic='2';.*name='dev-172\\.16\\.64 \\(Tony\\)';" ,descrip = "NSET-1-tonydev")
    nsid_2 = group_handle.nset_create_noinsertion(rname = "NSET-2-natwar-test2",regexpr = "ic='2';.*name='dev-172\\.16\\.45 \\(Natwar\\)';" ,descrip = "NSET-2-natwar-test2")

    dp_handle = DataplaneManagement(sut_handle)
    chassis_lst = dp_handle.get_chassis_list()
    for dpln_id in chassis_lst:
        dataplnid = int(dpln_id['id'])
        break

    dp_handle.ns_insertionstaging_elements(ns_id=nsid_1, nsname="NSET-1-tonydev", chassis_id=dataplnid, insertion_type="SEGMENTATION")
    dp_handle.ns_insertionstaging_elements(ns_id=nsid_2, nsname="NSET-2-natwar-test2", chassis_id=dataplnid, insertion_type="SEGMENTATION")

    ns_job_id_1 = dp_handle.ns_chassis_bulkinsertion(ns_id=nsid_1, chassis_id=dataplnid, insertion_type="SEGMENTATION")
    ns_job_id_2 = dp_handle.ns_chassis_bulkinsertion(ns_id=nsid_2, chassis_id=dataplnid, insertion_type="SEGMENTATION")

    time.sleep(500)

    job_handle = JobsApis(sut_handle)
    jobstatus_1 = job_handle.wait_on_job_by_id(ns_job_id_1)
    jobstatus_2 = job_handle.wait_on_job_by_id(ns_job_id_2)


    taskstat_1 = job_handle.get_tasks_by_job_id(ns_job_id_1)
    taskstat_2 = job_handle.get_tasks_by_job_id(ns_job_id_2)

    for taskstatus in taskstat_1:
        for taskstatus in taskstat_2:
            if taskstatus["state"] == 'COMPLETED' and taskstatus["status"] == 'PASSED':
                task_status = True

    if jobstatus_1 == True and task_status == True and jobstatus_2 == True :
        print("Network sets insertion completed successfully")

@pytest.mark.acl_policy_bats
def test_bats_001_acl_policy_list(sut_handle):
    accesslist = AccessControl(sut_handle)
    print("List of ACL's are:" ,accesslist.get_access_controllist())

@pytest.mark.acl_policy_bats
def test_bats_002_acl_policy_addrule(sut_handle):
    accesslist = AccessControl(sut_handle)
    rule_add = accesslist.add_access_control_rule()
    assert rule_add == True, "A new ACL rule added successfully"

@pytest.mark.acl_policy_bats
def test_bats_003_acl_addrule_srcdst(sut_handle):
    accesslist = AccessControl(sut_handle)
    rules_add = accesslist.add_srcdst_access_control_rule()
    assert rules_add == True, "ACL rules added with src and dst as RG's successfully"

@pytest.mark.acl_policy_bats
def test_bats_004_nondefault_acl_policy_create(sut_handle):
    accesslist = AccessControl(sut_handle)
    nondefacl = accesslist.add_nondefault_acl_policy()
    alist = accesslist.get_access_controllist()
    for ndacl in alist:
        if ndacl["name"] == 'nondefault_acl_policy':
            print("Non Default ACL policy creation successful")
            break

@pytest.mark.acl_policy_bats
def test_bats_005_acl_policy_multi_rule_create(sut_handle):
    accesslist = AccessControl(sut_handle)
    multirule = accesslist.add_multirule_httpping_service()
    alist = accesslist.get_access_controllist()
    for multiacl in alist:
        if multiacl["name"] == "Default ACL Policy":
            if multiacl["aclRules"][0]["name"] == "rule-2" and multiacl["aclRules"][1]["name"] == "rule-1":
                print("Multiple ACL rules added successfully")
            else:
                print("Failed to add ACL rules.")

@pytest.mark.acl_policy_bats
def test_bats_006_addrule_all_serviceid(sut_handle):
    accesslist = AccessControl(sut_handle)
    aclist = accesslist.get_access_controllist()
    for aid in aclist:
        if aid["name"] == 'Default ACL Policy':
            aclpolicyid = int(aid['id'])
            break

    payload_aclrule = [
        {
            "action": "PERMIT",
            "description": "New rule",
            "destinationApps": "",
            "destinationPortRanges": "",
            "destinationResourceGroupList": [
                0
            ],
            "enabled": True,
            "gmId": 0,
            "hitStats": {
                "earliestHitMS": 0,
                "hitCount": 0,
                "latestHitMS": 0,
                "ruleId": 0
            },
            "id": 0,
            "lastModified": 0,
            "mapOfChangeLogPerTS": {},
            "name": "new rule",
            "orderNum": 0,
            "packetCapture": "DISABLED",
            "serviceList": [
                215
            ],
            "sourceResourceGroupList": [
                0
            ],
            "spsId": 5,
            "syslog": False,
            "tcpSessionTimeout": 0,
            "tlsInspection": "DISABLED",
            "user": "admin",
            "userType": "HUMAN"
        }
    ]

    servicelst = [215, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 41, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 110, 109, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 159, 158, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 201, 200, 202, 203, 204, 205, 208, 209, 210, 211, 212, 206, 213, 207, 214]
    for slst in servicelst:
        for i in payload_aclrule:
            i["serviceList"] = [slst]
            rules_add = payload_aclrule
            alist_rules = accesslist.add_aclrule_aclpolicyid(rules_add,aclpolicyid)
            assert alist_rules == True, "Rule added successfully"

@pytest.mark.acl_policy_bats
def test_bats_007_addrule_all_appid(sut_handle, datadir):
    accesslist = AccessControl(sut_handle)
    aclist = accesslist.get_access_controllist()
    for aid in aclist:
        if aid["name"] == 'Default ACL Policy':
            aclpolicyid = int(aid['id'])
            break

    file_name = str((datadir/"dstapps.txt").resolve())
    with open(file_name ,'r') as infile:
        lines = infile.read()

    payload_aclrules = [
        {
            "action": "PERMIT",
            "description": "New Rule",
            "destinationPortRanges": "",
            "destinationResourceGroupList": [
                0
            ],
            "enabled": True,
            "gmId": 0,
            "hitStats": {
                "earliestHitMS": 0,
                "hitCount": 0,
                "latestHitMS": 0,
                "ruleId": 0
            },
            "id": 0,
            "lastModified": 0,
            "mapOfChangeLogPerTS": {},
            "name": "New Rule",
            "orderNum": 0,
            "packetCapture": "DISABLED",
            "serviceList": [
            ],
            "sourceResourceGroupList": [
                0
            ],
            "spsId": 5,
            "destinationApps": "100Bao",
            "syslog": False,
            "tcpSessionTimeout": 0,
            "tlsInspection": "DISABLED",
            "user": "admin",
            "userType": "HUMAN"
        }
    ]

    dst_apps = list(lines.split(","))
    # print(dst_apps)
    for dstids in dst_apps:
        for pyldacl in payload_aclrules:
            pyldacl["destinationApps"] = dstids
            rulesadd = payload_aclrules
            alist_rule = accesslist.add_aclrule_aclpolicyid(rulesadd, aclpolicyid)
            assert alist_rule == True, "Rule added successfully"

@pytest.mark.acl_policy_bats
def test_bats_008_acl_policy_tls_rule_create(sut_handle):
    task_status = False
    accesslist = AccessControl(sut_handle)
    tlsrule = accesslist.add_tls_rule()
    alist = accesslist.get_access_controllist()
    for tlsacl in alist:
        if tlsacl["name"] == "Default ACL Policy":
            if tlsacl["aclRules"][0]["tlsInspection"] == "INBOUND":
                print("TLS rule added successfully")
            else:
                print("Failed to enable TLS")

    time.sleep(480)
    dp_handle = DataplaneManagement(sut_handle)
    chassislst = dp_handle.get_chassis_list()

    for aid in chassislst:
        if aid["name"] == 'tonydp-qe' and aid["cloudType"] == 'VMWARE':
            vmware_chassisid = int(aid['id'])
            # print("Vmware",vmware_chassisid)
        elif aid["name"] == 'tonydp-qe' and aid["cloudType"] == 'AWS':
            aws_chassisid = int(aid['id'])
            # print("AWS",aws_chassisid)
        elif aid["name"] == 'tonydp-qe' and aid["cloudType"] == 'AZURE':
            azure_chassisid = int(aid['id'])
            # print("Azure",azure_chassisid)
        else:
            print("Failed to get chassis id")

    job_ids = dp_handle.get_redeploy_chassisid(vmware_chassisid)
    time.sleep(420)

    job_handle = JobsApis(sut_handle)
    jobstatus = job_handle.wait_on_job_by_id(job_ids)

    taskstat = job_handle.get_tasks_by_job_id(job_ids)
    for taskstatus in taskstat:
        if taskstatus["state"] == 'COMPLETED' and taskstatus["status"] == 'PASSED':
            task_status = True

    if jobstatus == True and task_status == True:
        print("After enable TLS , Redeploy job passed")

@pytest.mark.acl_policy_bats
def test_bats_09_del_nondefault_acl_policy(sut_handle):
    accesslist = AccessControl(sut_handle)
    del_nondefault_acl = accesslist.del_nondefaultacl_policy()
    assert del_nondefault_acl == True, "Non default ACL policy deleted successfully"

@pytest.mark.acl_policy_bats
def test_bats_0010_del_all_acl_policy_rules(sut_handle):
    accesslist = AccessControl(sut_handle)
    del_rules = accesslist.del_all_defaultacl_rules()
    assert del_rules == True, "All rules deleted from default ACL policy"
