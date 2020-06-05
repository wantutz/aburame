# standard library
import argparse
import os
import time

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.sxapi.rest_session import RestSession as SxSession
from sxswagger.sxapi.blacklist import Blacklist as BL

class BlacklistUpdate(object):
    def __init__(self, rest_session, logger):
        # Logger
        self.logger = logger

        # Session
        self.rest_session = rest_session

    def update(self, url):
        # Is imported?
        is_imported = False

        if url is not None:
            # System Management
            bl = BL(self.rest_session)
            is_imported = bl.import_listed_feed(url)
        else:
            self.logger.error("URL not provided.")

        return is_imported

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sample tool.")
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

    # Pick URL and update periodically
    if action == "url1":
        url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_180d.ipset"
    else:
        # Default URL
        url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bi_any_2_1d.ipset"

    try:
        # Initialize
        bl_update = BlacklistUpdate(sx_session, logger)

        while True:
            is_updated = bl_update.update(url)

            if is_updated:
                logger.info("Update is successful.")
            else:
                logger.error("Update has failed.")

            # Sleep until next update
            time.sleep(5 * 60)  # 5 minutes
    except KeyboardInterrupt as e:
        logger.info("Update task done. Goodbye.")
    except Exception as e:
        logger.error("Unknown exception: {}".format(e))
        
    # Logout
    sx_session.logout()

# Sample Run
# python update_blacklist.py -i 172.16.27.73 -u sxapi -p sxpass -a url1
