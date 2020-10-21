import pytest
import time

# shieldx library
from sxswagger.sxapi.cloud_management import CloudManagement as CloudMgmt
from sxswagger.sxapi.deployment_management import DeploymentManagement as DPMgmt
from sxswagger.sxapi.jobs_apis import JobsApis
from sxswagger.common.custom_config_reader import CustomConfigReader as CCR
from sxswagger.common.data_structure_converter import DataStructureConverter as DSC

@pytest.mark.cloud_bats
@pytest.mark.parametrize(
    "input_json_file", [
        ("aws.json"),
    ]
)
def test_create_deployment(sut_handle, shieldx_logger,
    datadir, input_json_file
):
    # Initialize
    cloud_mgmt = CloudMgmt(sut_handle)
    dp_mgmt = DPMgmt(sut_handle)

    config_reader = CCR()
    converter = DSC()

    resolved_input_json_file = str((datadir/input_json_file).resolve())
    aws_payload = dict(config_reader.read_json_config(resolved_input_json_file))

    aws_cloud = aws_payload["aws_cloud"]
    aws_deployment = aws_payload["aws_deployment"]

    cloud_name = aws_cloud["name"]
    cloud_infra = cloud_mgmt.get_cloud_infra_by_name(cloud_name)
    cloud_id = cloud_infra["id"]

    # Objects
    cloud_objects = cloud_mgmt.get_cloud_objects(cloud_id)
    networks = converter.list_of_dict_to_dict(cloud_objects["networks"], "name")
    tenants = converter.list_of_dict_to_dict(cloud_objects["tenants"], "name")

    #for key in cloud_objects:
    #    shieldx_logger.info("{}".format(key))
    #    #shieldx_logger.info("{} - {}".format(key, cloud_objects[key]))

    # Fill in deployment payload
    tenant_name = aws_deployment["deploymentSpecification"]["tenantNameStr"]
    mgmt_network_name = aws_deployment["deploymentSpecification"]["mgmtNetworkNameStr"]
    bkpln_network_name = aws_deployment["deploymentSpecification"]["backPlaneNetworkStr"]

    aws_deployment["cloudId"] = cloud_id
    aws_deployment["deploymentSpecification"]["cloudId"] = cloud_id
    aws_deployment["deploymentSpecification"]["cloudid"] = cloud_id
    aws_deployment["deploymentSpecification"]["regionId"] = tenants[tenant_name]["regionId"]
    aws_deployment["deploymentSpecification"]["tenantId"] = tenants[tenant_name]["id"]
    aws_deployment["deploymentSpecification"]["availabilityZoneId"] = networks[mgmt_network_name]["availabilityZoneId"]
    aws_deployment["deploymentSpecification"]["mgmtNetworkId"] = networks[mgmt_network_name]["id"]
    aws_deployment["deploymentSpecification"]["backPlaneNetworkId"] = networks[bkpln_network_name]["id"]
     
    shieldx_logger.info("DP - {}".format(aws_deployment))

    dp_id = dp_mgmt.create_deployment(aws_deployment)

    shieldx_logger.info("Deployment ID: {}".format(dp_id))
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
#  python3 -m pytest shieldxqe/test/func/test_deployment.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -m cloud_bats
#  python3 -m pytest shieldxqe/test/func/test_deployment.py -v --setup-show -s --um <umip> --username <user> --password <passwd> -k get_clouds
