# standard library
import os
import sys
import argparse
import requests

# shieldx library
from sxswagger.common.custom_logger import CustomLogger
from sxswagger.sxapi.rest_session import RestSession as SxSession

class VirtualPatchRG(object):
	def __init__(self, rest_session, logger, ip_list):
		#hardcoding URL with api key for now. need to understand how to issue the REST call using the SX_session
		url = "https://172.16.100.52/shieldxapi/v1/infras/resourcegroup?api_key=6Hm%2BgjxGhSL3%2BnQpda9uWMGpobxbqIDHDnwzdyZ4y5U%3D"
		member_list = []
		for ip in ip_list:
			ip2cidr = '"' + str(ip) + '/32"'
			member_list.append({"id":0,"cidr":ip2cidr})
		payload = {"infraIDs":[],"dynamic":false,"id":0,"name":"b","regex":null,"resourceType":"CIDR","description":"b","purpose":"POLICY","memberList":member_list}
		response = requests.post(url, data=payload, timeout=60, verify=False)
		return response
	

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Virtual Patch tool.")
    parser.add_argument("-i","--ipaddress", help="ShieldX - Mgmt. IP Address.", required=True)
    # parser.add_argument("-f","--inputjson", help="Input JSON containing Hosts to CVEs mapping.", required=True)
	ip_list = ["192.168.131.5","192.168.131.51"]
    parser.add_argument("-a","--action", default="info", help="Action", required=False)
    args = vars(parser.parse_args())

    # Take parameters
    # ip = args["ipaddress"]
    # username = os.environ.get("SHIELDX_USER")
    # password = os.environ.get("SHIELDX_PASS")
    ip = "172.16.100.52"
    username = "brijapi"
    password = "Admin@123"

    action = args["action"]

    # Initialize logger
    logger = CustomLogger().get_logger()

    if username is None or password is None:
        logger.warning("Please set username and password as environment variables.")
        sys.exit()

    # Establish REST connection
    sx_session = SxSession(ip=ip, username=username, password=password)
    sx_session.login()
	
	try:
		virtual_patch_rg = VirtualPatchRG(sx_session, logger, ip_list)
	
    except KeyboardInterrupt as e:
        logger.info("Task done. Goodbye.")
    except Exception as e:
        logger.error(e)
        
    # Logout
    sx_session.logout()

# Sample Run
# python create_resourcegroup.py -i 172.16.27.73 -f hosts_cves.json

# Payload
#{"infraIDs":[],"dynamic":false,"id":0,"name":"b","regex":null,"resourceType":"CIDR","description":"b","purpose":"POLICY","memberList":[{"id":0,"cidr":"192.168.131.5/32"},{"id":0,"cidr":"192.168.131.51/32"}]}