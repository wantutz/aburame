# standard library
import argparse

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.sxapi.rest_session import RestSession as SxSession
from sxswagger.sxapi.system_management import SystemManagement as SysMgmt

class EnableLicense(object):
    def __init__(self, rest_session, logger):
        # Logger
        self.logger = logger

        # Session
        self.rest_session = rest_session

    def activate(self, license):
        # Is activated?
        is_activated = False

        if license is not None:
            # System Management
            sys_mgr = SysMgmt(self.rest_session)
            is_activated = sys_mgr.set_license(license)
        else:
            self.logger.error("License not provided.")

        return is_activated

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enable License tool.")
    parser.add_argument("-i","--ipaddress", help="ShieldX - Mgmt. IP Address.", required=True)
    parser.add_argument("-u","--username", help="User name", required=False)
    parser.add_argument("-p","--password", help="User name", required=False)
    parser.add_argument("-a","--action", default="info", help="Action", required=False)
    args = vars(parser.parse_args())

    # Take parameters
    ip = args["ipaddress"]
    username = args["username"]
    password = args["password"]
    action = args["action"]

    # Initialize logger
    logger = CustomLogger().get_logger()

    # Establish REST connection
    sx_session = SxSession(ip=ip, username=username, password=password)
    sx_session.login()

    # Pick License
    if action == "devops":
        license = "0207ef1e-daac-547d-bcb1-82bf57607ab1"
    else:
        # Default License - DevOps, 2Gbps
        license = "0207ef1e-daac-547d-bcb1-82bf57607ab1"

    try:
        # Initialize
        enable_license = EnableLicense(sx_session, logger)

        license_enabled = enable_license.activate(license)

        if license_enabled: 
            logger.info("License ({}) activated.".format(license))
        else:
            logger.info("License ({}) activation failed.".format(license))
    except KeyboardInterrupt as e:
        logger.info("Update task done. Goodbye.")
    except Exception as e:
        logger.error("Unknown exception: {}".format(e))
        
    # Logout
    sx_session.logout()

# Sample Run
# python enabled_license.py -i 172.16.27.73 -u sxapi -p sxpass -a devops
