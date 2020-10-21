# standard library
import os
import time
import argparse

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.sxapi.rest_session import RestSession as SxSession
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

class StandaloneTool(object):
    def __init__(self):
        # Logger
        self.logger = CustomLogger().get_logger()

    def show_system_info(self, ip=None, username=None, password=None):
        if all([ip, username, password]):
            self.logger.info("Get system info.")

            # REST Session
            sx_session = SxSession(ip=ip, username=username, password=password)

            # Login 
            sx_session.login()

            # System Management
            sys_mgmt = SysMgmt(sx_session)
            sys_info = sys_mgmt.get_system_info()
            self.logger.info("System Info: {}".format(sys_info))

            # Logout
            sx_session.logout()
        else:
            self.logger.error("Missing parameters.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Standalone Tool that uses ShieldX Library')
    parser.add_argument('-i','--ipaddress', help='ShieldX - Mgmt. IP Address.', required=True)
    parser.add_argument('-u','--username', help='User name', required=False)
    parser.add_argument('-p','--password', help='User name', required=False)
    parser.add_argument('-a','--action', default="info", help='Action', required=False)
    args = vars(parser.parse_args())

    # Take parameters
    ip = args["ipaddress"]
    username = args["username"]
    password = args["password"]

    # Initialize
    standalone_tool = StandaloneTool()

    # Call method
    standalone_tool.show_system_info(ip, username, password)

# Sample Run
# python standalone_script.py -i 172.16.27.73 -u sxapi -p sxpass -a dummy
