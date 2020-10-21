import pytest
import time

# shieldx library
from sxswagger.sxapi.cloud_management import CloudManagement as CloudMgmt
from sxswagger.sxapi.jobs_apis import JobsApis
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR
from sxswagger.common.data_structure_converter import DataStructureConverter as DSC

@pytest.mark.cloud_bats
@pytest.mark.parametrize(
    "input_json_file", [
        ("aws.json"),
    ]
)
def test_create_aws_connector(sut_handle, shieldx_logger,
    datadir, input_json_file
):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)
    config_reader = CCR()
    converter = DSC()

    resolved_input_json_file = str((datadir/input_json_file).resolve())
    cloud_payload = dict(config_reader.read_json_config(resolved_input_json_file))

    aws_cloud = cloud_payload["aws_cloud"]

    # Fetch ACL Policy, Default ACL Policy = 3
    acl_id = 3
    aws_cloud["aclPolicyId"] = acl_id

    # Inline Inspection: Active | Passive
    pseudo_tap = "false"
    aws_cloud["inlinePassiveInspection"] = pseudo_tap
    
    # Create Infra Connector
    cloud_id = cloud_mgmt.create_cloud(aws_cloud)

    shieldx_logger.info("Cloud Type: {}".format("AWS"))
    shieldx_logger.info("Cloud ID: {}".format(cloud_id))
    shieldx_logger.info("---")

    # Initialize
    jobs_mgmt = JobsApis(sut_handle)

    jobs = jobs_mgmt.get_jobs()

    # Get Latest Job
    shieldx_logger.info("Jobs count: {}".format(len(jobs)))
    job = jobs[0]
    job_id = job["id"]

    # Monitor job progress
    is_completed = False
    retry = 0
    max_retry = 10
    time.sleep(60)

    while retry < max_retry:
         job = jobs_mgmt.get_job_by_id(job_id)
         shieldx_logger.info("Job {} - {} - {}".format(job["id"], job["state"], job["status"]))
         if job["state"] == "COMPLETED":
             break

         retry += 1
         time.sleep(60)

@pytest.mark.cloud_bats
@pytest.mark.parametrize(
    "input_json_file", [
        ("aws.json"),
    ]
)
def test_delete_aws_connector(sut_handle, shieldx_logger,
    datadir, input_json_file
):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    config_reader = CCR()

    resolved_input_json_file = str((datadir/input_json_file).resolve())
    cloud_payload = dict(config_reader.read_json_config(resolved_input_json_file))

    aws_cloud = cloud_payload["aws_cloud"]

    name = aws_cloud["name"]
    cloud_infra = cloud_mgmt.get_cloud_infra_by_name(name)
    cloud_id = cloud_infra["id"]

    shieldx_logger.info("Cloud Name: {}".format(name))
    shieldx_logger.info("Cloud ID: {}".format(cloud_id))
    shieldx_logger.info("---")

    # Delete
    cloud_mgmt.delete_cloud(cloud_id)

    # Initialize
    jobs_mgmt = JobsApis(sut_handle)

    jobs = jobs_mgmt.get_jobs()

    # Get Latest Job
    shieldx_logger.info("Jobs count: {}".format(len(jobs)))
    job = jobs[0]
    job_id = job["id"]

    # Monitor job progress
    is_completed = False
    retry = 0
    max_retry = 10
    time.sleep(60)

    while not is_completed and retry < max_retry:
         job = jobs_mgmt.get_job_by_id(job_id)

         if job["state"] == "COMPLETED":
             is_completed = True

         shieldx_logger.info("Job {} - {} - {}".format(job["id"], job["state"], job["status"]))
         retry += 1
         time.sleep(60)

@pytest.mark.cloud_bats
@pytest.mark.parametrize(
    "input_json_file", [
        ("aws.json"),
    ]
)
def test_get_aws_cloud_objects(sut_handle, shieldx_logger,
    datadir, input_json_file
):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    config_reader = CCR()
    converter = DSC()

    resolved_input_json_file = str((datadir/input_json_file).resolve())
    cloud_payload = dict(config_reader.read_json_config(resolved_input_json_file))

    aws_cloud = cloud_payload["aws_cloud"]

    name = aws_cloud["name"]
    cloud_infra = cloud_mgmt.get_cloud_infra_by_name(name)
    cloud_id = cloud_infra["id"]

    shieldx_logger.info("Cloud Name: {}".format(name))
    shieldx_logger.info("Cloud ID: {}".format(cloud_id))
    shieldx_logger.info("---")

    # Objects
    cloud_objects = cloud_mgmt.get_cloud_objects(cloud_id)

    #for key in cloud_objects:
    #    shieldx_logger.info("{}".format(key))
    #    #shieldx_logger.info("{} - {}".format(key, cloud_objects[key]))

    networks = converter.list_of_dict_to_dict(cloud_objects["networks"], "name")

    shieldx_logger.info("Network: {} - {}".format(networks["Juan-Management-Subnet"]["name"], networks["Juan-Management-Subnet"]["id"]))
    shieldx_logger.info("Network: {} - {}".format(networks["Juan-Backplane-Subnet"]["name"], networks["Juan-Management-Subnet"]["id"]))
    shieldx_logger.info("Network: {} - {}".format(networks["Juan-Workload-Subnet"]["name"], networks["Juan-Management-Subnet"]["id"]))

    tenants = converter.list_of_dict_to_dict(cloud_objects["tenants"], "name")
    shieldx_logger.info("Tenant: {} - {} - {}".format(tenants["Juan-Test-VPC"]["name"], tenants["Juan-Test-VPC"]["id"], tenants["Juan-Test-VPC"]["regionId"]))

@pytest.mark.cloud_bats
def test_get_clouds(sut_handle, shieldx_logger):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)

    # List Infra Connectors
    cloud_list = cloud_mgmt.get_cloud_infra()

    # Enumerate Infra Connectors
    for cloud_info in cloud_list:
        shieldx_logger.info("Cloud Type: {}".format(cloud_info["type"]))
        shieldx_logger.info("Cloud Name: {}".format(cloud_info["name"]))
        shieldx_logger.info("Cloud ID: {}".format(cloud_info["id"]))
        shieldx_logger.info("---")

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_cloud.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m cloud_bats
#  python3 -m pytest shieldxqe/test/func/test_cloud.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k create_infra
