# standard library
import json
import pytest
import time

# shieldx - jobs api
from sxswagger.sxapi.jobs_apis import JobsApis

# shieldx - system management
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

# shieldx - elastic search
from sxswagger.sxapi.elastic_search import ElasticSearch as ES

@pytest.mark.bats_jobs
def test_get_all_jobs(
    sut_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    jobs_mgmt = JobsApis(sut_handle)

    jobs = jobs_mgmt.get_jobs()

    for job in jobs:
        shieldx_logger.info("Job {} - {} - {}".format(job["id"], job["name"], job["status"]))

@pytest.mark.bats_jobs
def test_get_latest_jobs(
    sut_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    jobs_mgmt = JobsApis(sut_handle)

    jobs = jobs_mgmt.get_jobs()

    shieldx_logger.info("Jobs count: {}".format(len(jobs)))
    job = jobs[0]
    shieldx_logger.info("Job {} - {} - {}".format(job["id"], job["name"], job["status"]))

@pytest.mark.bats_jobs
def test_get_completed_jobs(
    sut_handle,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    jobs_mgmt = JobsApis(sut_handle)

    jobs = jobs_mgmt.get_jobs()

    if len(jobs) > 0:
        completed_jobs = [job for job in jobs if job["state"] == "COMPLETED"]
        shieldx_logger.info("Completed Jobs Count: {}".format(len(completed_jobs)))

        job_id = completed_jobs[0]["id"]
        job = jobs_mgmt.get_job_by_id(job_id)
        shieldx_logger.info("Job: {}".format(job))

        tasks = jobs_mgmt.get_tasks_by_job_id(job_id)
        shieldx_logger.info("Tasks: {}".format(tasks))
    else:
        shieldx_logger.error("Jobs not found.")

@pytest.mark.bats_jobs
@pytest.mark.parametrize("job_id", [101, 102])
def test_abort_job(
    sut_handle, job_id,
    shieldx_constants, shieldx_logger,
    datadir, pytestconfig
):
    # Initialize
    jobs_mgmt = JobsApis(sut_handle)

    job = jobs_mgmt.get_job_by_id(job_id)
    shieldx_logger.info("Job: {}".format(job))

    if job is not None:
        tasks = jobs_mgmt.get_tasks_by_job_id(job_id)
        shieldx_logger.info("Tasks: {}".format(tasks))

        is_aborted = jobs_mgmt.abort_job_by_id(job_id)
        shieldx_logger.info("Abort Status: {}".format(is_aborted))
    else:
        shieldx_logger.error("Job not found.")


# Sample run
#  python3 -m pytest shieldxqe/test/func/test_jobs.py -v --setup-show -s --shieldx --um <umip> --username <user> --password <passwd>
