#/*
#* ShieldX Networks Inc. CONFIDENTIAL
#* ----------------------------------
#*
#* Copyright (c) 2016 ShieldX Networks Inc.
#* All Rights Reserved.
#*
#* NOTICE:  All information contained herein is, and remains
#* the property of ShieldX Networks Incorporated and its suppliers,
#* if any.  The intellectual and technical concepts contained
#* herein are proprietary to ShieldX Networks Incorporated
#* and its suppliers and may be covered by U.S. and Foreign Patents,
#* patents in process, and are protected by trade secret or copyright law.
#* Dissemination of this information or reproduction of this material
#* is strictly forbidden unless prior written permission is obtained
#* from ShieldX Networks Incorporated.
#*/

# Author: tony
#
# Jobs Api's

# standard library

# 3rd party library
import json
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall

class JobsApis(object):
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # fetched data
        self.data = None

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # URLs specific to Jobs API
        self.jobs_url = "jobs/"

    def get_jobs(self):
        # Jobs
        jobs = []

        # Craft the URL
        url = self.rest_session.base_url + self.jobs_url

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        jobs = list(response.json())

        return jobs

    def get_job_by_id(self, job_id):
        # Job
        job = None

        # Craft the URL
        url = self.rest_session.base_url + self.jobs_url + str(job_id)

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       verify = False,
                       headers = headers
                   )

        # Convert response to expected data
        job = dict(response.json())

        return job

    def wait_on_job_by_id(self, job_id):
        job_completed = False

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.jobs_url + str(job_id) + "/wait"

            # Headers
            headers = self.rest_session.headers

            # Call REST - GET
            response = self.rest_call.get_query(
                url=url,
                verify=False,
                headers=headers
            )

            if response.status_code == requests.codes.ok:
                job_completed = True
                self.logger.info("Job completed successfully")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return job_completed

    def get_tasks_by_job_id(self, job_id):
        # Tasks
        tasks = []

        # Craft the URL
        url = self.rest_session.base_url + self.jobs_url + str(job_id) + "/tasks"

        # Headers
        headers = self.rest_session.headers

        # Call REST - GET
        response = self.rest_call.get_query(
            url=url,
            verify=False,
            headers=headers
        )

        tasks = list(response.json())

        return tasks

    def abort_job_by_id(self, job_id):
        is_job_aborted = False

        try:
            # Craft the URL
            url = self.rest_session.base_url + self.jobs_url + str(job_id) + "/abort"

            # Headers
            headers = self.rest_session.headers

            # Call REST - POST
            response = self.rest_call.post_query(
                url=url,
                verify=False,
                headers=headers
            )

            if response.status_code == requests.codes.ok:
                is_job_aborted = True
                self.logger.info("Job aborted successfully")
            else:
                self.logger.error(response.status_code)
        except Exception as e:
            self.logger.error(e)

        return is_job_aborted

if __name__ == "__main__":
    pass
