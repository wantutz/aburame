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

# standard library
import argparse
import logging
import os

class CustomLogger(object):

    def __init__(self):
        # get workspace
        self.workspace = os.getenv('HOME', './')

    def get_logger(self):
        # Log file
        log_file = "{workspace}/shieldx_qe.log".format(workspace=self.workspace)
        # Log level
        log_level = logging.INFO

        # logger
        self.logger = logging.getLogger(__name__)

        # Handlers, singleton - use single filename
        handler_stdout = logging.StreamHandler()
        handler_file = logging.FileHandler(log_file)

        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # Assign formatter to handler
        handler_stdout.setFormatter(formatter)
        handler_file.setFormatter(formatter)

        # Add handlers if None exist
        if not len(self.logger.handlers):
            self.logger.addHandler(handler_stdout)
            self.logger.addHandler(handler_file)
        else:
            pass

        # Level, singleton - set logging level for all log consumers
        self.logger.setLevel(log_level)

        # return logger
        return self.logger

class LogConsumer1:
    def __init__(self):
        self.logger = CustomLogger().get_logger()

        self.logger.debug("Log consumer (1) debug.")

class LogConsumer2:
    def __init__(self):
        self.logger = CustomLogger().get_logger()

        self.logger.info("Log consumer (2) info.")

class LogConsumer3:
    def __init__(self):
        self.logger = CustomLogger().get_logger()

        self.logger.warning("Log consumer (3) warning.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Custom Logger')
    args = vars(parser.parse_args())

    custom_logger = CustomLogger().get_logger()

    custom_logger.debug("Debug message.")
    custom_logger.info("Info message.")
    custom_logger.warning("Warning message.")
    custom_logger.error("Error message.")
    custom_logger.critical("Critical message.")

    LogConsumer1()
    LogConsumer2()
    LogConsumer3()
