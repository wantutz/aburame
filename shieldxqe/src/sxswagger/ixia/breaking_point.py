#!/usr/bin/python

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

# Author: Juan
# Breaking Point

# standard library
import os
import re
import time

# 3rd party library
import json
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.common.rest_call import RestCall
from sxswagger.ixia.real_time_stats import RealTimeStats

class BreakingPoint:
    def __init__(self, rest_session):
        # singleton logger
        self.logger = CustomLogger().get_logger()

        # REST Session
        self.rest_session = rest_session

        # Common REST Calls
        self.rest_call = RestCall(rest_session)

        # Test Info
        self.test_id = None
        self.test_iteration = None
        self.model_name = None

        # URLs specific to Breaking Point
        self.ports_url = "bps/ports"
        self.reserve_ports_url = "bps/ports/operations/reserve"
        self.unreserve_ports_url = "bps/ports/operations/unreserve"
        self.chassis_config_url = "bps/ports/chassisconfig"
        self.change_card_config_url = "bps/ports/operations/changecardconfig"
        self.reboot_card_url = "bps/ports/operations/rebootcard"
        self.running_tests_url = "bps/tests"
        self.start_test_url = "bps/tests/operations/start"
        self.stop_test_url = "bps/tests/operations/stop"
        self.get_rts_url = "bps/tests/operations/getrts"
        self.result = "bps/tests/operations/getrts"

        # Breaking Point constants
        self.TEST_COMPLETE = 100.0 # 100% complete
        self.BETWEEN_CHECKS = 1 * 60 # period for checking the stats

        self.RAMP_UP = 20.0 # Ramp up
        self.RAMP_DOWN = 80.0 # Ramp down

    def get_ports_status(self):
        # Port status
        ports_status = None

        # Craft the URL
        url = self.rest_session.base_url + self.ports_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Call REST - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Convert response to expected data
        ports_status = dict(response.json())

        return ports_status

    def reserve_ports(self, slot, ports):
        # Action
        is_reserved = False

        # Craft the URL
        url = self.rest_session.base_url + self.reserve_ports_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        data = json.dumps({"slot": slot, "portList": ports, "group": "1", "force": "true"})

        # Call REST - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_reserved = True
        else:
            is_reserved = False

        return is_reserved

    def unreserve_ports(self, slot, ports):
        # Action
        is_unreserved = False

        # Craft the URL
        url = self.rest_session.base_url + self.unreserve_ports_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        data = json.dumps({"slot": slot, "portList": ports})

        # Call REST - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_unreserved = True
        else:
            is_unreserved = False

        return is_unreserved

    def check_chassis_config(self, slot):
        # Action
        is_chassis_ready = False

        # Craft the URL
        url = self.rest_session.base_url + self.chassis_config_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Get chassis config - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        if response.status_code == requests.codes.ok:
            # Port Status
            chassis_config = dict(response.json())
            self.logger.info("Chassis Config: {}".format(chassis_config))

            if (len(chassis_config) > 0) and ("state" in chassis_config[slot]):
                if chassis_config[slot]["state"] == u"ok":
                    is_chassis_ready = True
                else:
                    self.logger.error("Chassis - ports are not ready.")
                    self.logger.error("State: {}".format(chassis_config[slot]["state"]))
            else:
                self.logger.error("Unable to fetch chassis config.")
        else:
            self.logger.error("Unable to fetch chassis config.")

        return is_chassis_ready

    def change_card_config(self, slot, action, mode):
        # Action
        is_card_config_changed = False

        # Craft the URL
        url = self.rest_session.base_url + self.change_card_config_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        data = json.dumps({"slot": slot, "action": action, "mode": mode})

        # Change Card Config
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_card_config_changed = True
        else:
            is_card_config_changed = False

        return is_card_config_changed

    def reboot_card(self, card_number):
        # Action
        is_rebooted = False

        # Craft the URL
        url = self.rest_session.base_url + self.reboot_card_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        data = json.dumps({"cardNumber": card_number})

        # Reboot card
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        # Convert response to expected data
        if response.status_code == requests.codes.ok:
            is_rebooted = True
        else:
            is_rebooted = False

        return is_rebooted

    def start_test(self, model_name):
        # Action
        is_started = False

        # Craft the URL
        url = self.rest_session.base_url + self.start_test_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        data = json.dumps({"modelname": model_name, "group": "1"})

        # Start Test - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        test_info = dict(response.json())

        # Get test info
        self.model_name = model_name
        self.test_id = test_info["testid"]
        self.test_iteration = test_info["iteration"]

        if response.status_code == requests.codes.ok:
            is_started = True

            self.logger.info("Model Name: {}".format(self.model_name))
            self.logger.info("Test ID: {}".format(self.test_id))
            self.logger.info("Test Iteration: {}".format(self.test_iteration))
        else:
            self.logger.error("Status Code: {}".format(response.status_code))

        return is_started

    def stop_test(self, test_id):
        # Action
        is_stopped = False

        # Craft the URL
        url = self.rest_session.base_url + self.stop_test_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        data = json.dumps({"testid": test_id})

        # Stop Test - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        if response.status_code == requests.codes.ok:
            is_stopped = True
        else:
            is_stopped = False

        return is_stopped

    def get_real_time_stats(self, test_id, stats_group="summary"):
        rts = None

        # Craft the URL
        url = self.rest_session.base_url + self.get_rts_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        if stats_group in RealTimeStats.STATSGROUP:
            data = json.dumps({"runid": test_id, "statsGroup": stats_group})
        else:
            data = json.dumps({"runid": test_id, "statsGroup": RealTimeStats.STATSGROUP[RealTimeStats.SUMMARY]})

        # Get RTS - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        if response.status_code == requests.codes.ok:
            rts = dict(response.json())
            self.logger.info("RTS: {}".format(rts))
        else:
            self.logger.error("Error: %d" % response.status_code)
            self.logger.error("Unable to get RTS.")

        return rts

    def get_running_tests(self, user):
        # test ID
        test_id = None

        # Craft the URL
        url = self.rest_session.base_url + self.running_tests_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Get Running Tests - GET
        response = self.rest_call.get_query(
                       url = url,
                       headers = headers,
                       verify = False
                   )

        # Test output
        testInfoRegExp = re.compile(r"""
                            TestId:\s+\[(.*?)\]\s+        # Test ID, index 1
                            Run\s+by:\s+\[(.*?)\]\s+      # Run by, index 2
                            State:\s+\[(.*?)\]\s+         # State
                            Progress:\s+\[(.*?)\]         # Progress
                         """, re.VERBOSE)

        if response.status_code == requests.codes.ok:
            self.logger.info("Response Text: %s" % response.text)
            runningTestsData = response.json()

            if len(runningTestsData) == 0:
                # Test is done, return testId = None
                return testId
            else:
                # Proceed
                pass

            try:
                for runningTestKey, runningTestValue in runningTestsData.items():
                    self.logger.debug("Running Test Key: >>%s<<, Running Test Value: >>%s<<" % (runningTestKey, runningTestValue))

                    if runningTestKey == 'runningTestInfo':
                        self.logger.info("%s -> %s" % (runningTestKey, runningTestValue))

                        # search test info
                        for testItem in runningTestValue.split(','):
                            testInfo = re.search(testInfoRegExp, testItem)

                            if user == testInfo.group(2):
                                self.logger.info("Test ID: %s" % testInfo.group(1))
                                testId = testInfo.group(1)
                                break
                            else:
                                self.logger.error("Test run by: >>%s<< == >>%s<<" % (user, testInfo.group(2)))
                                testId = None
                    else:
                        pass
            except Exception as e:
                self.logger.error("Running test not found, test is done.")
                self.logger.error(e)
        else:
            self.logger.error("Error: %d" % response.status_code)
            self.logger.error("Unable to get running tests.")

        return testId

    def get_result(self, test_id):
        result = None

        # Craft the URL
        url = self.rest_session.base_url + self.result_url

        # Headers
        headers = {
            'content-type': 'application/json;charset=utf-8',
            'Cookie': self.rest_session.cookie
        }

        # Payload
        data = json.dumps({"runid": test_id})

        # Get result - POST
        response = self.rest_call.post_query(
                       url = url,
                       headers = headers,
                       data = data,
                       verify = False
                   )

        if response.status_code == requests.codes.ok:
            result = dict(response.json())
        else:
            self.logger.error("Error: %d" % response.status_code)
            self.logger.error("Unable to get result.")

        return result

    def get_model_name(self):
        return self.model_name

    def get_test_id(self):
        if self.test_id is not None:
            return self.test_id
        else:
            return None

    def get_test_iteration(self):
        return self.test_iteration

    def send_strikes_traffic(self, slot, ports, traffic_profile):
        # BP - Real Time Stats
        bp_stats = RealTimeStats()

        # Summary Stats
        summary_stats = None

        # Processed Stats
        processed_stats = {
            "model_name": None,
            "test_id": None,
            "test_iteration": None,
            "total_strikes": None,
            "total_allowed": None,
            "total_blocked": None,
        }

        # Reserve Ports
        ports_reserved = self.reserve_ports(slot, ports)

        if ports_reserved:
            # Start test
            test_started = self.start_test(traffic_profile)

            if test_started:
                # Get test info
                test_id = self.get_test_id()
                test_iteration = self.get_test_iteration()


                # Breaking Point - Real Time Stats, extract progress
                rts = self.get_real_time_stats(test_id)
                progress = rts["progress"]

                # Monitor progress and proceed after test completed
                while float(progress) < self.TEST_COMPLETE:
                    # Wait before the next progress check
                    time.sleep(self.BETWEEN_CHECKS)

                    # Get RTS based on Test ID, extract progress
                    rts = self.get_real_time_stats(test_id)
                    progress = rts["progress"]

                # Breaking Point - Test run completed, extract results
                self.logger.critical("RTS[rts]: {}".format(rts["rts"]))
                summary_stats = bp_stats.parse_stats(rts["rts"])

                self.logger.info("Total Strikes: {}".format(summary_stats["totalStrikes"]))
                self.logger.info("Total Allowed: {}".format(summary_stats["totalAllowed"]))
                self.logger.info("Total Blocked: {}".format(summary_stats["totalBlocked"]))

                # Populate processed stats
                processed_stats["model_name"] = traffic_profile
                processed_stats["test_id"] = test_id.lstrip("TEST-")
                processed_stats["test_iteration"] = test_iteration

                processed_stats["total_strikes"] = summary_stats["totalStrikes"]
                processed_stats["total_allowed"] = summary_stats["totalAllowed"]
                processed_stats["total_blocked"] = summary_stats["totalBlocked"]
            else:
                self.logger.error("Unable to start test.")
        else:
            self.logger.error("Unable to reserve ports.")

        # Release Ports
        ports_freed = self.unreserve_ports(slot, ports)

        if ports_freed:
            self.logger.info("Ports released.")
        else:
            self.logger.error("Unable to release ports.")

        return processed_stats

    def send_perf_traffic(self, slot, ports, traffic_profile):
        # BP - Real Time Stats
        bp_stats = RealTimeStats()

        # Summary Stats
        summary_stats = None

        # Processed Stats
        processed_stats = {
            "model_name": None,
            "test_id": None,
            "test_iteration": None,
            "avg_tx_tput": None,
            "avg_rx_tput": None,
            "avg_tcp_response_time": None,
        }
        # Stats precision for throughput and response time
        PRECISION = 2

        tx_frame_data_rate = []
        rx_frame_data_rate = []
        tcp_response_time = []

        # Reserve Ports
        ports_reserved = self.reserve_ports(slot, ports)

        if ports_reserved:
            # Start test
            test_started = self.start_test(traffic_profile)

            if test_started:
                # Get test info
                test_id = self.get_test_id()
                test_iteration = self.get_test_iteration()

                # Breaking Point - Real Time Stats, extract progress
                rts = self.get_real_time_stats(test_id)
                progress = rts["progress"]

                # Monitor progress and proceed after test completed
                while float(progress) < self.TEST_COMPLETE:
                    # Wait before the next progress check
                    time.sleep(self.BETWEEN_CHECKS)

                    # Get RTS based on Test ID, extract progress
                    rts = self.get_real_time_stats(test_id)
                    progress = rts["progress"]

                    if (progress >= self.RAMP_UP and progress <= self.RAMP_DOWN):
                        # Capture stats during "Steady State"
                        summary_stats = bp_stats.parse_stats(rts["rts"])

                        # Append stats
                        tx_frame_data_rate.append(float(summary_stats["ethTxFrameDataRate"]))
                        rx_frame_data_rate.append(float(summary_stats["ethRxFrameDataRate"]))
                        tcp_response_time.append(float(summary_stats["tcpAvgResponseTime"]))
                    else:
                        # Ignore stats during "Ramp Up" and "Ramp Down"
                        pass

                # Test completed, progress is 100%
                # Compute average
                avg_tx_frame_data_rate = (sum(tx_frame_data_rate) / len(tx_frame_data_rate))
                avg_rx_frame_data_rate = (sum(rx_frame_data_rate) / len(rx_frame_data_rate))
                avg_tcp_response_time = (sum(tcp_response_time) / len(tcp_response_time))

                # Populate processed stats
                processed_stats["model_name"] = traffic_profile
                processed_stats["test_id"] = test_id.lstrip("TEST-")
                processed_stats["test_iteration"] = test_iteration

                processed_stats["avg_tx_tput"] = round(avg_tx_frame_data_rate, PRECISION)
                processed_stats["avg_rx_tput"] = round(avg_rx_frame_data_rate, PRECISION)
                processed_stats["avg_tcp_response_time"] = round(float(avg_tcp_response_time), PRECISION)
            else:
                self.logger.error("Unable to start test.")
        else:
            self.logger.error("Unable to reserve ports.")

        # Release Ports
        ports_freed = self.unreserve_ports(slot, ports)

        if ports_freed:
            self.logger.info("Ports released.")
        else:
            self.logger.error("Unable to release ports.")

        return processed_stats

    def send_cps_traffic(self, slot, ports, traffic_profile):
        # BP - Real Time Stats
        bp_stats = RealTimeStats()

        # Summary Stats
        summary_stats = None

        # Processed Stats
        processed_stats = {
            "model_name": None,
            "test_id": None,
            "test_iteration": None,
            "avg_tcp_client_established_rate": None,
            "avg_tcp_server_established_rate": None,
            "avg_tcp_response_time": None,
        }
        # Stats precision for CPS and response time
        PRECISION = 2

        tcp_client_established_rate = []
        tcp_server_established_rate = []
        tcp_response_time = []

        # Reserve Ports
        ports_reserved = self.reserve_ports(slot, ports)

        if ports_reserved:
            # Start test
            test_started = self.start_test(traffic_profile)

            if test_started:
                # Get test info
                test_id = self.get_test_id()
                test_iteration = self.get_test_iteration()

                # Breaking Point - Real Time Stats, extract progress
                rts = self.get_real_time_stats(test_id)
                progress = rts["progress"]

                # Monitor progress and proceed after test completed
                while float(progress) < self.TEST_COMPLETE:
                    # Wait before the next progress check
                    time.sleep(self.BETWEEN_CHECKS)

                    # Get RTS based on Test ID, extract progress
                    rts = self.get_real_time_stats(test_id)
                    progress = rts["progress"]

                    if (progress >= self.RAMP_UP and progress <= self.RAMP_DOWN):
                        # Capture stats during "Steady State"
                        summary_stats = bp_stats.parse_stats(rts["rts"])

                        # Append stats
                        tcp_client_established_rate.append(float(summary_stats["tcpClientEstablishRate"]))
                        tcp_server_established_rate.append(float(summary_stats["tcpServerEstablishRate"]))
                        tcp_response_time.append(float(summary_stats["tcpAvgResponseTime"]))
                    else:
                        # Ignore stats during "Ramp Up" and "Ramp Down"
                        pass

                # Test completed, progress is 100%
                # Compute average
                avg_tcp_client_established_rate = (sum(tcp_client_established_rate) / len(tcp_client_established_rate))
                avg_tcp_server_established_rate = (sum(tcp_server_established_rate) / len(tcp_server_established_rate))
                avg_tcp_response_time = (sum(tcp_response_time) / len(tcp_response_time))

                # Populate processed stats
                processed_stats["model_name"] = traffic_profile
                processed_stats["test_id"] = test_id.lstrip("TEST-")
                processed_stats["test_iteration"] = test_iteration

                processed_stats["avg_tcp_client_established_rate"] = round(avg_tcp_client_established_rate, PRECISION)
                processed_stats["avg_tcp_server_established_rate"] = round(avg_tcp_server_established_rate, PRECISION)
                processed_stats["avg_tcp_response_time"] = round(float(avg_tcp_response_time), PRECISION)
            else:
                self.logger.error("Unable to start test.")
        else:
            self.logger.error("Unable to reserve ports.")

        # Release Ports
        ports_freed = self.unreserve_ports(slot, ports)

        if ports_freed:
            self.logger.info("Ports released.")
        else:
            self.logger.error("Unable to release ports.")

        return processed_stats


    def send_app_traffic(self, slot, ports, traffic_profile):
        # BP - Real Time Stats
        bp_stats = RealTimeStats()

        # Summary Stats
        summary_stats = None

        # Processed Stats
        processed_stats = {
            "model_name": None,
            "test_id": None,
            "test_iteration": None,
            "avg_tx_tput": None,
            "avg_rx_tput": None,
            "avg_tcp_client_established_rate": None,
            "avg_tcp_server_established_rate": None,
            "avg_tcp_response_time": None,
        }
        # Stats precision
        PRECISION = 2

        # Stats
        tx_frame_data_rate = []
        rx_frame_data_rate = []
        tcp_client_established_rate = []
        tcp_server_established_rate = []
        tcp_response_time = []

        # Reserve Ports
        ports_reserved = self.reserve_ports(slot, ports)

        if ports_reserved:
            # Start test
            test_started = self.start_test(traffic_profile)

            if test_started:
                # Get test info
                test_id = self.get_test_id()
                test_iteration = self.get_test_iteration()

                # Breaking Point - Real Time Stats, extract progress
                rts = self.get_real_time_stats(test_id)
                progress = rts["progress"]

                # Monitor progress and proceed after test completed
                while float(progress) < self.TEST_COMPLETE:
                    # Wait before the next progress check
                    time.sleep(self.BETWEEN_CHECKS)

                    # Get RTS based on Test ID, extract progress
                    rts = self.get_real_time_stats(test_id)
                    progress = rts["progress"]

                    if (progress >= self.RAMP_UP and progress <= self.RAMP_DOWN):
                        # Capture stats during "Steady State"
                        summary_stats = bp_stats.parse_stats(rts["rts"])

                        # Append stats - data rate
                        tx_frame_data_rate.append(float(summary_stats["ethTxFrameDataRate"]))
                        rx_frame_data_rate.append(float(summary_stats["ethRxFrameDataRate"]))

                        # Append stats - establish rate
                        tcp_client_established_rate.append(float(summary_stats["tcpClientEstablishRate"]))
                        tcp_server_established_rate.append(float(summary_stats["tcpServerEstablishRate"]))

                        # Append stats - response time
                        tcp_response_time.append(float(summary_stats["tcpAvgResponseTime"]))
                    else:
                        # Ignore stats during "Ramp Up" and "Ramp Down"
                        pass

                # Test completed, progress is 100%
                # Compute average data rate
                avg_tx_frame_data_rate = (sum(tx_frame_data_rate) / len(tx_frame_data_rate))
                avg_rx_frame_data_rate = (sum(rx_frame_data_rate) / len(rx_frame_data_rate))
                avg_tcp_response_time = (sum(tcp_response_time) / len(tcp_response_time))
                # Compute average establish rate
                avg_tcp_client_established_rate = (sum(tcp_client_established_rate) / len(tcp_client_established_rate))
                avg_tcp_server_established_rate = (sum(tcp_server_established_rate) / len(tcp_server_established_rate))
                # Compute average TCP response time
                avg_tcp_response_time = (sum(tcp_response_time) / len(tcp_response_time))

                # Populate processed stats
                processed_stats["model_name"] = traffic_profile
                processed_stats["test_id"] = test_id.lstrip("TEST-")
                processed_stats["test_iteration"] = test_iteration
                # Data rate
                processed_stats["avg_tx_tput"] = round(avg_tx_frame_data_rate, PRECISION)
                processed_stats["avg_rx_tput"] = round(avg_rx_frame_data_rate, PRECISION)
                # CPS
                processed_stats["avg_tcp_client_established_rate"] = round(avg_tcp_client_established_rate, PRECISION)
                processed_stats["avg_tcp_server_established_rate"] = round(avg_tcp_server_established_rate, PRECISION)
                # TCP response time
                processed_stats["avg_tcp_response_time"] = round(float(avg_tcp_response_time), PRECISION)
            else:
                self.logger.error("Unable to start test.")
        else:
            self.logger.error("Unable to reserve ports.")

        # Release Ports
        ports_freed = self.unreserve_ports(slot, ports)

        if ports_freed:
            self.logger.info("Ports released.")
        else:
            self.logger.error("Unable to release ports.")

        return processed_stats

if __name__ == '__main__':
    pass
