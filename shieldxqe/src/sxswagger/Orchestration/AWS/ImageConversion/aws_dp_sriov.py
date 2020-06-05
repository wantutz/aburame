from __future__ import print_function
import boto3
from multiprocessing import Process, Pool, Lock, Manager
from botocore.exceptions import ClientError
from configobj import ConfigObj as CO
import sys
import json
import re
import os
import optparse
from time import sleep
import warnings
from copy import deepcopy
import logging
import multiprocessing
import traceback
from pprint import pprint


# Author: Vamsi
# Date: 12/13/2017
# Error Failure mod: 3/18/2019
# add support for 2.0: 7/9/2019
# fix the versions- 9/23/2019
# add support for 2.0MR: 8/15/2019
# add support for 2.1: 11/15/2019
# add image check: 12/5/2019
# fix the bugs: 12/16/2019


class ImageConversion(object):
	def __init__(self, cfg_file=None):
		self.config = Manager().dict()
		if cfg_file is not None:
			self.cfg_file = cfg_file
		else:
			self.cfg_file = '../Configs/aws2.cfg'
		self.config = CO(infile=self.cfg_file)
		if self.config == {}:
			print("Can not read from the Config File: {}".format(self.cfg_file))
			sys.exit(1)
		warnings.warn('Do not open or change the config file while the script is running!!!')
		self.lock = Lock()
		self.outer_lock = Lock()
		self.stateful = self.config['STATEFUL']
		self.scale_vtag = self.config['SCALE_VTAG']
		self.states = deepcopy(self.stateful)
		self.access_key = self.config['AWS']['ACCESS_KEY']
		self.secret_key = self.config['AWS']['SECRET_KEY']
		self.region = self.config['AWS']['REGION']
		self.account_id = self.config['AWS']['ACCOUNT_ID']
		self.mntpt = self.config['MOUNT_POINT']
		self.bucket = self.config['S3']['NAME']
		self.to_deploy = self.config['TO_DEPLOY']['NAMES']
		self.import_config = self.config['IMPORT_IMAGE']
		self.dp_name = None
		self.um_name = None
		self.scale_lc_name = None
		if 'dp' in self.to_deploy:
			# if dp needs to be uploaded and imported
			self.dp_name = self.config['DP_SRIOV']['NAME']
			self.dp_location = self.mntpt + self.config['DP_SRIOV']['DP_LOCATION']
			# getting the dp_version when current folder is given
			loc = self.config['DP_SRIOV']['DP_LOCATION']
			if 'current' in loc:
				build_list = os.listdir(self.dp_location.rstrip('current/ami-dp-linecard.vmdk'))
				self.dp_version = str(max([int(i) for i in build_list if i.isdigit()]))
				if 'Master' in loc or 'master' in loc:
					if 'Master' in loc:
						loc_master = 'Master'
					else:
						loc_master = 'master'
					self.dp_version = '{}.0.'.format(loc_master) + self.dp_version
				elif 'SXREL1.2' in loc:
					self.dp_version = '1.2.' + self.dp_version
				elif 'SXREL1.3' in loc:
					self.dp_version = '1.3.' + self.dp_version
				elif 'SXREL1.4' in loc:
					self.dp_version = '1.4.' + self.dp_version
				elif 'SXREL2.' in loc.upper():
					if 'SXREL2.0MR1' in loc.upper():
						self.dp_version = '2.0mr1.' + self.dp_version
					elif 'SXREL2.0' in loc.upper():
						self.dp_version = '2.0.' + self.dp_version
					else:
						self.dp_version = '2.1.' + self.dp_version
				print("current DP Version: ", self.dp_version)
			else:
				if 'Master' in loc or 'master' in loc:
					if 'Master' in loc:
						loc_master = 'Master'
						dp = "Datapath"
						jenkins = "jenkins"
					else:
						loc_master = 'master'
						dp = 'DataPath'
						jenkins = "jenkins2"
					self.dp_version = loc.split("{}/{}/{}/".format(jenkins, loc_master, dp))[1].rstrip(
						"/ami-dp-linecard.vmdk")
					self.dp_version = '{}.0.'.format(loc_master) + self.dp_version
					print("Master Version: ", self.dp_version)
				elif 'SXREL1.2' in loc:
					self.dp_version = "1.2." + loc.split('jenkins/SXREL1.2/Datapath/')[1].rstrip(
						'/ami-dp-linecard.vmdk')
					print("SXREL 1.2 DP Version: ", self.dp_version)
				elif 'SXREL1.3' in loc:
					self.dp_version = "1.3." + loc.split('jenkins/SXREL1.3/Datapath/')[1].rstrip(
						'/ami-dp-linecard.vmdk')
				elif 'SXREL1.4' in loc:
					self.dp_version = "1.4." + loc.split('jenkins/SXREL1.4/Datapath/')[1].rstrip(
						'/ami-dp-linecard.vmdk')
				elif "sxrel2." in loc.lower():
					if "sxrel2.0mr1" in loc.lower():
						self.dp_version = "2.0mr1." + loc.split("jenkins2/sxrel2.0mr1/DataPath/")[1].rstrip(
							'/ami-dp-linecard.vmdk')
					elif "sxrel2.0" in loc.lower():
						self.dp_version = "2.0." + loc.split("jenkins2/sxrel2.0/DataPath/")[1].rstrip(
							'/ami-dp-linecard.vmdk')
					else:
						self.dp_version = "2.1." + loc.split("jenkins2/sxrel2.1/DataPath/")[1].rstrip(
							'/ami-dp-linecard.vmdk')
				else:
					# self.logger.error("DP String is incorrect: Please check aws2.cfg")
					print("DP String is incorrect: Please check cfg file")
					sys.exit(1)
			if 'master' in loc or 'Master' in loc:
				self.dp_ami_name = self.import_config['TAG_M']['DP_NAME'] + '-' + str(self.dp_version)
			else:
				self.dp_ami_name = self.import_config['TAG']['DP_NAME'] + '-' + str(self.dp_version)
		self.img_name = ''
		# case: what if you want to deploy only dp and not the UM and Scale
		if 'um' in self.to_deploy or 'scale' in self.to_deploy:
			# if um and scale needs to be uploaded
			# Getting UM details
			if 'um' in self.to_deploy:
				um_location_string = self.mntpt + self.config['UM']['UM_LOCATION_STRING']
				self.version = self.config['VERSION']
				print(self.version)
				strng = 'ShieldX'
				location_um = um_location_string.split(strng)
				um_string = strng + location_um[1]
				um_match = re.compile(um_string)
				vmdks = os.listdir(location_um[0])
				print(vmdks)
				print(um_string)
				um = [x for x in vmdks if um_match.match(x)]
				# patch - to fix the um missing
				if um == [] and "um" in self.to_deploy:
					# self.logger.error("\nERROR: UM Build not present in the specified path: Please verify\n")
					print("\nERROR: UM Build not present in the specified path: Please verify\n")
					sys.exit(1)
				else:
					self.um_name = um[0]
					if self.version.lower() == 'shieldx':
						if "sxrel2.1" in location_um[0].lower() or "sxrel2.0" in location_um[0].lower() or "master" in \
								location_um[0]:
							vm_string = "ShieldX-ESP"
						else:
							vm_string = 'ShieldX-APIERO-'
						self.um_build = self.um_name.strip('-ami.vmdk').strip(vm_string)
						self.um_location = location_um[0] + self.um_name
						self.image_version = self.um_build
					elif self.version.lower() == 'master':
						loc_master = None
						if 'Master' in self.um_name:
							loc_master = 'Master'
						elif 'master' in self.um_name:
							loc_master = 'master'
						self.um_build = self.um_name.strip('-ami.vmdk').strip('ShieldX-ESP-{}.'.format(loc_master))
						self.um_location = location_um[0] + self.um_name
						self.image_version = 'Master.0.' + self.um_build
					else:
						# self.logger.error("Provide correct version of the image in the config file: ShieldX or Master")
						print("Provide correct version of the image in the config file: ShieldX or Master")
						sys.exit(1)
				self.um_ami_name = self.um_name + '-' + self.um_build
			if 'scale' in self.to_deploy:
				# only if scale is present in the self.to_deploy
				scale_lc = self.mntpt + self.config['SCALE']['LC_LOCATION']
				if "current" in scale_lc:
					b = scale_lc.split('current/ami-scale-linecard.vmdk')[0]
					build_list = os.listdir(b)
					build_number = str(max([int(i) for i in build_list if i.isdigit()]))
					if "sxrel2.1" in b.lower() or "sxrel2.0" in b.lower() or "master" in b.lower():
						vm_string = "ShieldX-ESP"
					else:
						vm_string = 'ShieldX-APIERO-'
					self.um_name = "{}-{}.".format(vm_string, self.scale_vtag + build_number + "-ami.vmdk")
					self.image_version = self.scale_vtag + build_number
					self.um_build = self.scale_vtag + build_number

				# a change made to allow the scale image upload
				else:
					jenkins = None
					loc_master = None
					if 'Master' in scale_lc or 'master' in scale_lc:
						if 'Master' in scale_lc:
							loc_master = 'Master'
							jenkins = "jenkins"
						elif 'master' in scale_lc:
							loc_master = 'master'
							jenkins = "jenkins2"
						version = scale_lc.split("{}/{}/Management/".format(jenkins, loc_master))[1].rstrip(
							"/ami-scale-linecard.vmdk")
						scale_version = '{}.0.'.format(loc_master) + version
						print("Master Scale Version: ", scale_version)
					elif 'SXREL1.2' in scale_lc:
						scale_version = "1.2." + scale_lc.split('/ami-scale-linecard.vmdk')[0].split("/")[-1]
						print("SXREL 1.2 Scale Version: ", scale_version)
					elif 'SXREL1.3' in scale_lc:
						scale_version = "1.3." + scale_lc.split('/ami-scale-linecard.vmdk')[0].split("/")[-1]
						print("SXREL 1.3 Scale Version: ", scale_version)
					elif 'SXREL1.4' in scale_lc:
						scale_version = "1.4." + scale_lc.split('/ami-scale-linecard.vmdk')[0].split("/")[-1]
						print("SXREL 1.4 Scale Version: ", scale_version)
					elif 'SXREL2.' in scale_lc.upper():
						if 'SXREL2.0MR1' in scale_lc.upper():
							scale_version = "2.0mr1." + scale_lc.split('/ami-scale-linecard.vmdk')[0].split("/")[-1]
						elif "SXREL2.0" in scale_lc.upper():
							scale_version = "2.0." + scale_lc.split('/ami-scale-linecard.vmdk')[0].split("/")[-1]
						else:
							scale_version = "2.1." + scale_lc.split('/ami-scale-linecard.vmdk')[0].split("/")[-1]
					else:
						# self.logger.error("DP String is incorrect: Please check aws2.cfg")
						print("Scale String is incorrect: Please check aws2.cfg")
						sys.exit(1)
					if 'um' not in self.to_deploy:
						self.image_version = scale_version
						self.um_build = scale_version
				self.scale_ami_name = self.import_config['TAG']['SCALE_NAME'] + "-" + self.um_build
				self.scale_lc_name = self.config['SCALE']['LC_NAME']
				self.scale_lc_location = self.mntpt + self.config['SCALE']['LC_LOCATION']
			print("\nUM version: ", self.image_version)
		self.policy_name = self.config['IAM_POLICY']['POLICY_NAME']
		self.role_name = self.config['IAM_POLICY']['ROLE_NAME']
		self.img_architecture = self.import_config['ARCHITECTURE']
		self.img_description = self.import_config['DESCRIPTION']
		self.img_format = self.import_config['FORMAT']
		self.export_img_name = self.config['EXPORT_IMAGE']['NAME']
		self.export_img_description = self.config['EXPORT_IMAGE']['DESCRIPTION']
		self.overwrite_spec = self.config['UPLOAD_SPEC']['OVERWRITE']
		self.overwrite = False
		if self.overwrite_spec == 'yes':
			self.overwrite = True
		self.dp_image_id = ''
		self.um_image_id = ''
		self.scale_image_id = ''
		self.instance_id = ''
		self.export_image = None
		self.task_resp = ''
		self.status = ''
		self.image_id = ''
		# if state or no state- do the below part
		self.s3_con = boto3.client('s3', region_name=self.region, aws_access_key_id=self.access_key,
		                           aws_secret_access_key=self.secret_key)
		self.iam_con = boto3.client('iam', region_name=self.region, aws_access_key_id=self.access_key,
		                            aws_secret_access_key=self.secret_key)
		self.ec2_con = boto3.client('ec2', region_name=self.region, aws_access_key_id=self.access_key,
		                            aws_secret_access_key=self.secret_key)
		self.ec2_resource = boto3.resource('ec2', region_name=self.region, aws_access_key_id=self.access_key,
		                                   aws_secret_access_key=self.secret_key)

	def log_handler(self, logfile):
		logFile = logfile
		logLevel = logging.INFO
		logger = logging.getLogger(__name__)
		handlerStdout = logging.StreamHandler()
		handlerFile = logging.FileHandler(logFile)
		formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
		handlerStdout.setFormatter(formatter)
		handlerFile.setFormatter(formatter)
		if not len(logger.handlers):
			logger.addHandler(handlerStdout)
			logger.addHandler(handlerFile)
		else:
			pass
		logger.setLevel(logLevel)
		return logger

	def display_progress(self, status, percent):
		pass

	def image_already_exist(self, ami_name):
		try:
			images = self.ec2_con.describe_images(Filters=[{"Name": "tag:AMI Name", "Values": [ami_name]}])
		except Exception as e:
			print("Error while checking for existing images for: {}:".format(ami_name))
			print(e)
			# sys.exit(1)
			return False
		else:
			if len(images["Images"]) == 0:
				print("Image doesnt exist with the ami-name: {}".format(ami_name))
				return False
			else:
				print("Image already exist with the tag:AMI Name: {}".format(ami_name))
				return True

	def create_bucket(self):
		"""
		change: if bucket exists, skip creation
		:return:
		"""
		print('\n ------ Creating Bucket ------ \n')
		# from what I read s3_con.create_bucket is an idempotent operation: so, it creates the bucket or returns the
		#  existing bucket the creation operation will succeed(unchanged bucket) in US region. But, in non-us regions,
		#  it will throw an BucketAlreadyOwnedByYou error (this is what I got for the ireland region)
		try:
			check_bucket = self.s3_con.head_bucket(Bucket=self.bucket)
		except ClientError as e:
			# self.logger.warn("Bucket with this name does not exist ", e)
			print("Bucket with this name does not exist ", e)
			# self.logger.info("Creating the S3 bucket: ", self.bucket)
			print("Creating the S3 bucket: ", self.bucket)
			try:
				if self.region == 'us-east-1':
					create_resp = self.s3_con.create_bucket(ACL='private', Bucket=self.bucket)
				else:
					create_resp = self.s3_con.create_bucket(ACL='private', Bucket=self.bucket,
					                                        CreateBucketConfiguration={
						                                        'LocationConstraint': self.region})
			except Exception as e:
				print("Got exception while creating S3 Bucket: ", e)
				exc_type, exc_value, exc_tb = sys.exc_info()
				pprint(traceback.format_exception(exc_type, exc_value, exc_tb))
				sys.exit(1)
			else:
				r = create_resp['ResponseMetadata']
				status = r['HTTPStatusCode']
				if status == 200:
					# self.logger.info("Bucket Created Successfully at {}".format(create_resp['Location']))
					print("Bucket Created Successfully at {}".format(create_resp['Location']))
					# issue while fetching the bucket: https://github.com/boto/boto3/issues/280 - unresolved
					# so, I will do a stupid workaround :
					retries = 0
					while retries < 5:
						try:
							self.s3_con.head_bucket(Bucket=self.bucket)
							return r['HostId']
						except ClientError as CE:
							sleep(5)
							retries += 1
				else:
					print("Creation of Bucket Failed", r['HTTPStatusCode'])
					print(create_resp)
					sys.exit(1)
		except Exception as err:
			print("Error Fetching bucket information: ", err)
			exc_type, exc_value, exc_tb = sys.exc_info()
			pprint(traceback.format_exception(exc_type, exc_value, exc_tb))
			sys.exit(1)
		else:
			print(check_bucket)
			print("Bucket exists! Skipped Bucket Creation")

	def upload_image_file(self, file_location=None, file_name=None):
		print("Current process: ", multiprocessing.current_process().name)
		if file_location is not None:
			image_location = file_location
		else:
			print("File location parameter is missing")
			sys.exit(1)
		if file_name is not None:
			self.img_name = file_name
		overwrite = self.overwrite
		if os.path.exists(image_location):
			print("\n File exists in the Local path\n")
		else:
			print("File does not exists in the Local path: check the mount location!!!")
			sys.exit(1)
		# check whether the object exist in the S3 bucket
		try:
			verify_object = self.s3_con.head_object(Bucket=self.bucket, Key=self.img_name)
			print("Object Exists: ", self.img_name)
			object_exist = True
		except Exception:
			object_exist = False
			pass
		if object_exist is True and overwrite is False:
			print("Since Object exists and overwrite is not set, Skipping upload for {} \n".format(self.img_name))
			return None
		elif object_exist is True and overwrite is True:
			print("Overwrite is set: Uploading Image and overwriting existing one\n")
		print("Uploading ", self.img_name)
		self.s3_con.upload_file(image_location, self.bucket, self.img_name)
		print("File Upload Done... wait until the object exists")
		waiter = self.s3_con.get_waiter('object_exists')
		waiter.wait(Bucket=self.bucket, Key=self.img_name)
		check_object = self.s3_con.head_object(Bucket=self.bucket, Key=self.img_name)
		if check_object['ResponseMetadata']['HTTPStatusCode'] == 200:
			print("\nFile: {} Uploaded Successfully\n".format(file_name))
		else:
			print("\nFile: {} not uploaded to the S3 Bucket successfully\n".format(file_name))
			sys.exit(1)

	def check_role_and_create_role(self):
		trust_policy = {'Version': '2012-10-17', 'Statement': [
			{'Action': 'sts:AssumeRole', 'Effect': 'Allow', 'Condition':
				{'StringEquals': {'sts:Externalid': 'vmimport'}},
			 'Principal': {'Service': 'vmie.amazonaws.com'}}]}
		try:
			# check if the role being created already exists
			myrole = self.iam_con.get_role(RoleName=self.role_name)
			print("The Role already exists: ", myrole)
			return True
		except Exception as role_error:
			# if it doesnt exist: lets create one
			print("Unable to get the Role: ", role_error)
			try:
				# create role
				print("Creating Role")
				role_res = self.iam_con.create_role(AssumeRolePolicyDocument=json.dumps(trust_policy), Path='/',
				                                    RoleName=self.role_name)
				print(role_res)
				print("Role got Created {}".format(self.role_name))
				return True
			except Exception as err_role:
				# got error while creating the role: exit
				print("Error while dealing with Roles: ", err_role)
				sys.exit(1)

	def create_role_policy(self):
		"""
			change: If exists skip create policy
			:return:
		"""
		print("\n\n ----- Role-Policy Creation ----- \n")
		iam_policy = {"Version": "2012-10-17", "Statement": [
			{"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource":
				["arn:aws:s3:::{}".format(self.bucket)]},
			{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::{}/*".format(self.bucket)]},
			{"Effect": "Allow", "Action":
				["ec2:ModifySnapshotAttribute", "ec2:CopySnapshot", "ec2:RegisterImage", "ec2:Describe*"],
			 "Resource": "*"}]}
		test_arn = 'arn:aws:iam::{}:policy/{}'.format(self.account_id, self.policy_name)
		try:
			# check for the policy
			check_policy_resp = self.iam_con.get_policy(PolicyArn=test_arn)
			print("Policy Exists: \n", check_policy_resp)
		except Exception as e:
			# no policy: lets create policy
			print("Policy Doesnt exist")
			print(e)
			print("\n ----- Creating a new policy ----- \n")
			trust_policy = {'Version': '2012-10-17', 'Statement': [
				{'Action': 'sts:AssumeRole', 'Effect': 'Allow', 'Condition': {
					'StringEquals': {'sts:Externalid': 'vmimport'}}, 'Principal': {'Service': 'vmie.amazonaws.com'}}]}

			policy_resp = self.iam_con.create_policy(PolicyName=self.policy_name, PolicyDocument=json.dumps(iam_policy))
			if policy_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Policy Created Succeessfully! \n PolicyId: ", policy_resp['Policy']['PolicyId'])
				print("Creating a Role and Attaching it to the created Policy: {}".format(
					policy_resp['Policy']['PolicyName']))
				arn = policy_resp['Policy']['Arn']
			else:
				print("Failed to create policy: ", policy_resp)
				sys.exit(1)
			# policy creation succeeded, now look in to the Roles
			print("\n------- Role Creation ----------\n")
			print("Check if the Role exists")
			try:
				# check if the role being created already exists
				role = self.iam_con.get_role(RoleName=self.role_name)
				print("The Role already exists: ", role)
			except Exception as role_err:
				# if it doesnt exist: lets create one
				print("Unable to get the Role: ", role_err)
				try:
					# create role
					print("Creating Role")
					role_resp = self.iam_con.create_role(AssumeRolePolicyDocument=json.dumps(trust_policy), Path='/',
					                                     RoleName=self.role_name)
					print("Role Created {}".format(self.role_name))
					print("Response: {}".format(role_resp))
				except Exception as e:
					# got error while creating the role: exit
					print("Error while dealing with Roles: ", e)
					sys.exit(1)
				else:
					# if role creation successful
					print("\nPolicy- Role Creation Successful")
					print("Attaching Role to the Policy ")
					try:
						# if the role creation success or even if it already exists: lets attach to the policy
						self.iam_con.attach_role_policy(PolicyArn=arn, RoleName=self.role_name)
						print("Attached Role to the Policy")
						print("sleeping for 10 seconds.... (for policy to load)")
						sleep(10)
					except Exception as err:  # got error while attaching role to policy : exit
						print("Error Attaching Role to the Policy: ", err)
						sys.exit(1)
		else:
			# if the policy exists: for safe usage: lets update the Role and other params
			print("------")
			print("\nModifying the existing policy\n")
			role_creation = self.check_role_and_create_role()
			if role_creation is True:
				print("Set Policy")
				modify_policy = self.iam_con.put_role_policy(
					RoleName=self.role_name,
					PolicyName=self.policy_name,
					PolicyDocument=json.dumps(iam_policy))
				print("Policy Updated \n", modify_policy)
				return None

	def verify_rolepolicy_creation(self):
		sleep(15)
		try:
			role_policy = self.iam_con.get_role_policy(RoleName=self.role_name, PolicyName=self.policy_name)
			if role_policy['RoleName'] == self.role_name and role_policy['PolicyName'] == self.policy_name:
				print("Verification: Role policy created and exists", role_policy)
			else:
				print("Role policy doesnt exist", role_policy)
				sys.exit(1)
		except Exception as e:
			print("Got an exception while fetching the role policy", e)
			sys.exit(1)
		else:
			return role_policy

	def import_image(self, image_object_name=None, img_id=None, task_id=None, state=False, wait_complete=False,
	                 cut_recursive=None):
		"""
		aws ec2 import-image --region ${4} --disk-containers \[\{\"Description\":\"${1}\",\ \"Format\":\"vmdk\",\ \"UserBucket\":\{\"S3Bucket\":\"${2}\",\ \"S3Key\":\"${3}\"\}\}\]
		Change: upload all three images
		:return:
		"""
		if state is True:
			resp, pos = self.verify_image_state(imgs_id=img_id, import_task_id=task_id)
			if resp == 'waiting':
				# task not completed
				print("\nImage not available yet: task is under process")
				r = self.wait_for_import(import_task_id=task_id, image_name=image_object_name)
				if r == 'Done':
					print("Wait Complete")
					self.import_image(image_object_name=image_object_name, task_id=task_id, wait_complete=True)
			elif resp == 'Exit':
				# got an error -> clean state and exit out
				self.write_import_state(img_name=image_object_name, task_id=task_id, im_state='clean',
				                        outer_lck=self.outer_lock)
			else:
				# returned response -> task finished or image available
				if pos == 'sure':  # if image available -> provided image_id in IDone case
					print("\nImport Done, Image is available.\n")
					print(resp)
					"""
					{u'Images': [{u'VirtualizationType': 'hvm', u'Description': 'AWS-VMImport service: Linux - Other Linux - 3.13.0-116-generic', u'Tags': [{u'Value': 'shieldx-dp-v1_2_mr3-99', u'Key': 'AMI Name'}, {u'Value': 'shieldx-dp-v1_2_mr3', u'Key': 'Name'}, {u'Value': '99', u'Key': 'imageVersion'}], u'Hypervisor': 'xen', u'ImageId': 'ami-14774371', u'State': 'available', u'BlockDeviceMappings': [{u'DeviceName': '/dev/sda1', u'Ebs': {u'Encrypted': False, u'DeleteOnTermination': False, u'VolumeType': 'gp2', u'VolumeSize': 41, u'SnapshotId': 'snap-0dfe1691025424921'}}], u'Architecture': 'x86_64', u'ImageLocation': '471729719052/import-ami-fgxlxtat', u'RootDeviceType': 'ebs', u'OwnerId': '471729719052', u'RootDeviceName': '/dev/sda1', u'CreationDate': '2018-02-07T18:27:39.000Z', u'Public': False, u'ImageType': 'machine', u'Name': 'import-ami-fgxlxtat'}], 'ResponseMetadata': {'RetryAttempts': 0, 'HTTPStatusCode': 200, 'RequestId': '7fc2ba46-47bc-4223-82bf-f3a62aa74ba4', 'HTTPHeaders': {'transfer-encoding': 'chunked', 'vary': 'Accept-Encoding', 'server': 'AmazonEC2', 'content-type': 'text/xml;charset=UTF-8', 'date': 'Wed, 07 Feb 2018 19:14:42 GMT'}}}
					"""
					try:
						self.image_id = resp['ImportImageTasks'][0]['ImageId']
						self.status = resp['ImportImageTasks'][0]['Status']
						print("import operation got completed\n")
					except Exception as e:
						print(" Getting from the new kind of resp object:")
						self.image_id = resp['Images'][0]['ImageId']
						self.status = resp['Images'][0]['State']
						print("import operation got completed\n")
				elif pos == 'unsure':  # only import task finished.. checking for image availability
					# provided task ID and got the task complete status
					print("Response:", resp)
					print("\nImport Done... Image should be available...Verifying...\n")
					self.image_id = resp['ImportImageTasks'][0]['ImageId']
					self.status = resp['ImportImageTasks'][0]['Status']
				# come out of the parent if state block
		elif state is False:
			if wait_complete is not True:  # havent waited for import to complete... 1st time may be
				if image_object_name is not None:
					self.img_name = image_object_name
					print(self.img_name)
				import_resp = self.ec2_con.import_image(Architecture=self.img_architecture,
				                                        DiskContainers=[{'Description': self.img_description,
				                                                         'Format': self.img_format,
				                                                         'UserBucket': {'S3Bucket': self.bucket,
				                                                                        'S3Key': self.img_name}}],
				                                        RoleName=self.role_name)
				print(import_resp)
				# image_id = import_resp['ImageId']
				import_task_id = import_resp['ImportTaskId']
				task_id = import_task_id
				print("Maintaining State...")
				self.write_import_state(img_name=image_object_name, task_id=task_id, im_state="pre_import",
				                        outer_lck=self.outer_lock)
				# waiter = self.ec2_con.get_waiter('image_available')
				print("\nWaiting for Image import to finish.....")
				wait_result = self.wait_for_import(import_task_id=import_task_id, image_name=image_object_name)
				if wait_result == 'Done':
					self.task_resp = self.ec2_con.describe_import_image_tasks(
						ImportTaskIds=['{}'.format(import_task_id)])
					self.status = self.task_resp['ImportImageTasks'][0]['Status']
					self.image_id = self.task_resp['ImportImageTasks'][0]['ImageId']
				# come out of the parent elif state-> False block
			elif wait_complete is True:  # after wait complete from the previous step
				self.task_resp = self.ec2_con.describe_import_image_tasks(ImportTaskIds=['{}'.format(task_id)])
				self.status = self.task_resp['ImportImageTasks'][0]['Status']
				self.image_id = self.task_resp['ImportImageTasks'][0]['ImageId']
			# come out of the parent elif state-> False  block

		# if state or no state- do the below part
		print("State Change... maintaining states")
		self.write_import_state(img_name=image_object_name, task_id=task_id, im_state="IDone",
		                        outer_lck=self.outer_lock)
		if self.status == 'completed' or self.status == 'available':
			print("Import Task Completed: \n", self.task_resp)
			print("\n Task Status is completed...verifying if the image really exists or not..\n")
			i_resp = self.ec2_con.describe_images(ImageIds=[self.image_id])
			if i_resp['Images'][0]['State'] == 'available':
				print("Image Available\n")
				return self.image_id
			else:
				print("Image Not Available: Importing the image again")
				if cut_recursive is True:
					print("\nNot doing import for the second time... Exit Out\n")
					sys.exit(1)
				elif cut_recursive is None:
					print("Importing the missing image... \n")
					self.import_image(image_object_name=image_object_name, cut_recursive=True)
		else:
			print("\nImage Import Status is not completed: Image Doesn't exist \n", self.task_resp)
			print("\nExiting out... Please clear the state and try again for this image: \n", image_object_name)

	def verify_image_state(self, imgs_id, import_task_id):
		try:
			resp = self.ec2_con.describe_images(ImageIds=[imgs_id])
			if resp['Images'][0]['State'] == 'available':
				return resp, 'sure'
			else:
				return 'waiting', None
		except Exception as e:
			print("VerificationWarning: Verificaion ImageId: ", e)
			print("Image doesnt exist yet: checking for the task status")
			try:
				task_resp = self.ec2_con.describe_import_image_tasks(ImportTaskIds=['{}'.format(import_task_id)])
				if task_resp['ImportImageTasks'][0]['Status'] == 'completed':
					return task_resp, 'unsure'
				elif task_resp['ImportImageTasks'][0]['Status'] == 'active':
					return 'waiting', None
			except Exception as e:
				print("Error: Verification: ", e)
				print("Task status is also not present: Remove state in config file: Abort")
				return "Exit", None

	def write_import_state(self, img_name, task_id, im_state, outer_lck):
		outer_lck.acquire()
		print("Outer Lock acquired")
		image_object_name = img_name
		if image_object_name == self.dp_name:
			self.dp_image_id = self.image_id
			if im_state == 'pre_import':
				ivalue = [im_state, None, self.dp_name, task_id]
			elif im_state == 'clean':
				ivalue = []
			elif im_state == 'IDone':
				ivalue = [im_state, self.dp_image_id, self.dp_name, task_id]
			else:
				print("Unknown state")
				sys.exit(1)
			self.maintain_state(key='dp', value=ivalue, lck=self.lock)
		elif image_object_name == self.um_name:
			self.um_image_id = self.image_id
			if im_state == 'pre_import':
				ivalue = [im_state, None, self.um_name, task_id]
			elif im_state == 'clean':
				ivalue = []
			else:
				ivalue = [im_state, self.um_image_id, self.um_name, task_id]
			self.maintain_state(key='um', value=ivalue, lck=self.lock)
		elif image_object_name == self.scale_lc_name:
			self.scale_image_id = self.image_id
			if im_state == 'pre_import':
				ivalue = [im_state, None, self.scale_lc_name, task_id]
				print(ivalue)
			elif im_state == 'clean':
				ivalue = []
			else:
				ivalue = [im_state, self.scale_image_id, self.scale_lc_name, task_id]
			self.maintain_state(key='scale', value=ivalue, lck=self.lock)
		print("Releasing outer lock")
		outer_lck.release()

	def wait_for_import(self, import_task_id, image_name):
		progress = 0
		status = 0
		iteration = 0
		if image_name == self.dp_name:
			i_name = 'dp'
		elif image_name == self.um_name:
			i_name = 'um'
		elif image_name == self.scale_lc_name:
			i_name = 'scale'
		try:
			while (progress != 100 or status != 'completed') and iteration < 500:
				iteration += 1
				task_resp = self.ec2_con.describe_import_image_tasks(ImportTaskIds=[import_task_id])
				try:
					progress = task_resp['ImportImageTasks'][0]['Progress']
				except KeyError as e:
					sleep(2)
					status = task_resp['ImportImageTasks'][0]['Status']
					if status == 'completed':
						break
					elif status == 'deleted':
						print("Error in importing the UM: Task Status: ", status)
						sys.exit(1)
					else:
						print("Error: ".format(e))
				status = task_resp['ImportImageTasks'][0]['Status']
				if i_name == 'scale':
					print("{}:        ---- Progress: {} |  Status: {} ----\n".format(i_name, progress, status))
				else:
					print("{}:           ---- Progress: {} |  Status: {} ----\n".format(i_name, progress, status))
				if iteration >= 500:
					print("Took so much time to import...")
					resp = str(input('Do you want to continue?: If yes Enter yes'))  # raw_input became input in python3
					if resp == 'yes':
						iteration = 0
					else:
						print("Itetrations Finished")
						sys.exit(1)
				if progress < 90:
					sleep(60)
				else:
					sleep(15)
			return "Done"
		except Exception as e:
			print("Error: ", e)

	def tag_image(self, import_image_id, img_name, return_id=None):
		"""
		Change: Add tags for all the image_ids
		:return:
		"""
		print("\n\n----- Tagging Image ----- \n")
		if img_name not in ['dp', 'um', 'scale']:
			print("ERROR: name should be any of ['dp', 'um', 'scale']")
			sys.exit(1)

		try:
			image = self.ec2_resource.Image(import_image_id)
			if img_name == 'dp':
				print("Tagging DP image")
				if 'Master' in self.dp_version:
					dp_name = self.import_config['TAG_M']['DP_NAME']
				else:
					dp_name = self.import_config['TAG']['DP_NAME']

				tag = image.create_tags(Tags=[{'Key': 'Name', 'Value': dp_name},
				                              {'Key': 'AMI Name', 'Value': self.dp_ami_name},
				                              {'Key': 'imageVersion', 'Value': str(self.dp_version)}])
				if return_id is not None:
					self.dp_image_id = return_id
			elif img_name == 'um':
				print("Tagging UM image")
				tag = image.create_tags(
					Tags=[{'Key': 'Name', 'Value': self.import_config['TAG']['UM_NAME'] + str(self.um_build)},
					      {'Key': 'AMI Name', 'Value': self.um_ami_name},
					      {'Key': 'imageVersion', 'Value': self.image_version}])
			elif img_name == 'scale':
				print("Tagging Scale-Linecard Image")
				if 'Master' in self.image_version:
					scale_name = self.import_config['TAG_M']['SCALE_NAME']
				else:
					scale_name = self.import_config['TAG']['SCALE_NAME']
				tag = image.create_tags(Tags=[{'Key': 'Name', 'Value': scale_name},
				                              {'Key': 'AMI Name', 'Value': self.scale_ami_name},
				                              {'Key': 'imageVersion', 'Value': self.image_version}])
			else:
				print("Unknown img_name")
				print(sys.exc_info())
				sys.exit(1)
		except Exception as error:
			print(error)
		else:
			print("Tag created successfully: ", tag)

	def launch_instance(self, image_id=None):
		print("\n\n ----- Launching Instance from the Image ----- \n")
		try:
			if image_id is not None:
				self.dp_image_id = image_id
			instance_launch = self.ec2_resource.create_instances(
				ImageId=self.dp_image_id,
				MinCount=1,
				MaxCount=1,
				KeyName=self.config['LAUNCH']['KEYNAME'],
				InstanceType=self.config['LAUNCH']['DEVICE'],
				UserData='{ "sx_config_boot" : "True" }',
				BlockDeviceMappings=[{
					'DeviceName': self.config['LAUNCH']['DEVICE_NAME'], 'Ebs': {'DeleteOnTermination': True}}],
				NetworkInterfaces=[
					{
						'DeviceIndex': 0,
						'SubnetId': self.config['LAUNCH']['SUBNET_ID'],
						'AssociatePublicIpAddress': True,
						'Groups': [self.config['LAUNCH']['SECURITY_GROUP_ID']],
					},
				]
			)
		except Exception as e:
			print("Error in launching instance: ", e)
			sys.exit(1)
		else:
			self.instance_id = instance_launch[0].id
			self.ec2_resource.create_tags(
				Resources=[self.instance_id],
				Tags=[{'Key': 'Name', 'Value': self.config['LAUNCH']['NAME']}])
			print("Instance created!!!", instance_launch)
			return self.instance_id

	def deregister_imported_image(self):
		print("\n\n------- Deregistering the imported image ------- \n")
		image = self.ec2_resource.Image(self.dp_image_id)
		try:
			image.deregister()
		except Exception as e:
			print("Deregister Error: ", e)
			sys.exit(1)

	def stop_instance_and_enable_sriov(self, instance_id=None):
		"""
		sriov-net-support - value: 'simple' indicates that enhanced networking
		with the Intel 82599 VF interface is enabled.
		:return:
		"""
		try:
			if instance_id is not None:
				self.instance_id = instance_id
			print("\n\n ----- Stop instance and Enable the SRIOV ----- \n")
			print("Confirm the Instance existence: ")
			instance = self.ec2_resource.Instance(self.instance_id)
			instance.wait_until_exists()
			if instance.state['Name'] != 'stopped':
				print(instance.state)
				instance.wait_until_running()
				print("Instance State: ", instance.state)
				instance.stop()
				print("Instance Stop Operation initiated... \nWaiting until the instance stops")
				instance.wait_until_stopped()
				print("Instance Stopped: ", instance.state)
			elif instance.state['Name'] == 'stopped':
				print("Instance already in 'stopped' state: Skipping Stop operation")
			else:
				print("State: ", instance.state)
				sys.exit(1)
			print("Enabling SRIOV")
			sriov_resp = self.ec2_con.modify_instance_attribute(InstanceId=self.instance_id,
			                                                    SriovNetSupport={'Value': 'simple'})
			s = instance.describe_attribute(Attribute='sriovNetSupport')
			if s['SriovNetSupport']['Value'] == 'simple':
				print("SRIOV is enabled successfully")
		except Exception as err:
			print("Error Exception in stop_instance_and_enable_sriov: ", err)
			sys.exit(1)

	def export_image_and_delete_instance(self, instance_id=None):
		print('\n\n ------ Export image and Delete the launched instance ------ \n')
		if instance_id is not None:
			self.instance_id = instance_id
		instance = self.ec2_resource.Instance(self.instance_id)
		image_resp = instance.create_image(Name=self.export_img_name + str(self.dp_version),
		                                   Description=self.export_img_description)
		self.export_image = self.ec2_resource.Image(image_resp.id)
		exp_id = image_resp.id
		try:
			print("Tagging new image")
			self.tag_image(import_image_id=exp_id, img_name='dp')
			self.export_image.wait_until_exists()
			sleep(15)  # sleep for 15 seconds
			if self.export_image.state == 'available':
				print("Image {} Created; State-> :".format(self.export_img_name), self.export_image.state)
			else:
				print("Image Not Available: State->  {}".format(self.export_image.state))

			print("Deleting the previous instance: ", instance.tags)
			instance.terminate()
			instance.wait_until_terminated()
			print("Instance got teminated \n Job Done ")
			print(instance.state)
		except Exception as e:
			print("Error in export image and delete instance: ", e)
			sys.exit(1)

	def maintain_state(self, key, value, lck):
		lck.acquire()
		print("\nLock Acquired")
		self.config = CO(infile=self.cfg_file)
		self.config['STATEFUL'][key] = value
		self.config.write()
		print("\n\n---------- Applying State -----------\n")
		print("{} got the state-config: {} \n".format(key, value))
		self.config = CO(infile=self.cfg_file)
		print("Verify Config: ", self.config['STATEFUL'])
		print("Releasing Lock\n")
		lck.release()
		print("Lock Released\n")

	def import_and_tag_thread(self, image_object_name, image_key, task_id=None, img_id=None, state=False):
		ion = image_object_name
		print("\nImport process started for {} \n".format(ion))
		image_key = image_key
		if task_id is not None:
			task_id = task_id
		if img_id is not None:
			img_id = img_id
		if state is not False:
			state = state
		image_id = self.import_image(image_object_name=ion, img_id=img_id, task_id=task_id, state=state)
		print("\nImport process for {} done!\n".format(ion))
		try:
			self.tag_image(import_image_id=image_id, img_name=image_key)
			if image_key == 'dp':
				print("\nProcess Finished Importing {}; Continuing to next steps\n".format(ion))
				self.streamline_dp_operations()
				self.maintain_state(key='dp', value=["Done"], lck=self.lock)
			else:
				self.maintain_state(key=image_key, value=["Done"], lck=self.lock)
				print("\nProcess Finished Importing {} \n".format(ion))
		except Exception as e:
			print("Error in Import_and_Tag_Thread: ", e)
			sys.exit(1)

	def streamline_dp_operations(self):
		# launch the dp instance and get instance id
		self.launch_instance()
		# de-register the old image
		self.deregister_imported_image()
		# stop instance and enable the SRIOV
		self.stop_instance_and_enable_sriov()
		# export image from instance and then delete the instance
		self.export_image_and_delete_instance()


def parse_args():
	# addon-> can provide arguments too!
	parser = optparse.OptionParser()
	parser.add_option('-a', '--autorun', dest='auto_run', help='Set auto run to True to wait for build input')
	parser.add_option('-d', '--dp', dest='dp_build', help='Enter the dp_build')
	parser.add_option('-f', '--cfg', dest='cfg_file', default='aws2.cfg',
	                  help='Provide the configuration file (ex: abcd.cfg)')
	parser.add_option('-u', '--um', dest='um_build', help='provide the um build number ex: 432')
	return parser.parse_args()


def pool_func(func, rgs):
	pool = Pool(processes=4)
	results = [pool.apply_async(func, args=rgs)]
	output = [p.get() for p in results]
	print(output)


if __name__ == '__main__':
	(options, args) = parse_args()
	if options.cfg_file != 'aws2.cfg':
		cfg_file = options.cfg_file
	else:
		cfg_file = None
	self = ImageConversion(cfg_file=cfg_file)

	if options.auto_run is True:
		print("Auto Run is true: Accepting arguments")
		if options.dp_build:
			dp_build = options.dp_build
		else:
			dp_build = None
		if options.um_build:
			um_build = options.um_build  # if stable take from the aws config
		else:
			um_build = None
		if self.version.lower() == 'shieldx':
			if dp_build is not None:
				self.dp_location = '{u}/jenkins2/sxrel2.1/DataPath/{a}/ami-dp-linecard.vmdk'.format(u=self.mntpt,
				                                                                                    a=dp_build)
			# build_dir = um_build.split('.')[2]
			if um_build is not None:
				self.um_location = '{u}/jenkins/sxrel2.1/Management/{a}/ShieldX-ESP-2.1.{a}-ami.vmdk'.format(
					u=self.mntpt, a=um_build)
				self.scale_lc_location = '{}/jenkins/sxrel2.0/Management/{}/ami-scale-linecard.vmdk'.format(self.mntpt,
				                                                                                            um_build)
		elif self.version.lower() == 'master':
			if dp_build is not None:
				self.dp_location = '{}/jenkins/Master/DataPath/{}/ami-dp-linecard.vmdk'.format(self.mntpt, dp_build)
			if um_build is not None:
				self.um_location = '{u}/jenkins/Master/Management/{a}/ShieldX-ESP-{a}-ami.vmdk'.format(u=self.mntpt,
				                                                                                       a=um_build)
				self.scale_lc_location = '{}/jenkins/Master/Management/{}/ami-scale-linecard.vmdk'.format(self.mntpt,
				                                                                                          um_build)
			# worker = Pool(4)  # creating a pool of 4 worker process threads
	self.create_bucket()
	image_dict = {}
	for i in self.to_deploy:
		if i == 'dp':
			if not self.image_already_exist(ami_name=self.dp_ami_name):
				image_dict['dp'] = {'location': self.dp_location, 'name': self.dp_name}
		elif i == 'um':
			if not self.image_already_exist(ami_name=self.um_ami_name):
				image_dict['um'] = {'location': self.um_location, 'name': self.um_name}
		elif i == 'scale':
			if not self.image_already_exist(ami_name=self.scale_ami_name):
				image_dict['scale'] = {'location': self.scale_lc_location, 'name': self.scale_lc_name}
		"""
		# to upload only selective images
		if self.to_deploy is not [] or self.to_deploy is not None:
			images = [i for i in image_dict if i not in self.to_deploy]
			for i in images:
				image_dict.pop(i)
			"""
	print("Images: ", image_dict)
	# upload image to S3 bucket
	print("\n\n ------ Uploading Images From Jenkins to S3 Bucket -------\n")
	proc_list = []
	for i in image_dict:
		location = image_dict[i]['location']
		name = image_dict[i]['name']
		print("\n Uploading {} to {} from {}\n".format(name, self.bucket, location))
		keywords = {'file_location': location, 'file_name': name}
		try:
			procs = Process(target=self.upload_image_file, name='S3_Upload_process: {}'.format(name), kwargs=keywords)
			proc_list.append(procs)
		except KeyboardInterrupt as k:
			print("Received keyboard interrupt from the user")
			for proc in proc_list:
				proc.join()
			sys.exit(1)
		except Exception as e:
			print("Error: ", e)
			sys.exit(1)
	print("Starting all the processes")
	for i in proc_list:
		i.start()

	print("process list: ", proc_list)
	for i in proc_list:
		print("pid of {} : {}".format(i.name, i.pid))
		i.join()
		print("S3 Upload {} Processes Joined\n".format(i.name))
	# sleep(1)
	# create role and policy
	print("\nAll upload processes Joined!!!")
	self.create_role_policy()
	print("Sleeping 10 seconds before the policy gets added and proceed to import!!!")
	sleep(10)
	self.verify_rolepolicy_creation()
	# import image to your region from the bucket
	print("\n\n------ Importing Images from S3 to your region ------\n")
	# case: if to_deploy is set to upload only specific images-> then modify the states to
	print("Reconfiguring stateful values according to TO_DEPLOY")
	# print(self.to_deploy
	for i in ['dp', 'scale', 'um']:
		if i not in image_dict:
			print(i)
			self.states.pop(i)
	import_processes = []
	exit_codes = []
	try:
		state_vals = max([len(self.states[i]) for i in self.states])
	except Exception as e:
		print("Unable to retrieve stateful values: ", e)
		pass
	else:  # I will always succeed in getting the state attributes  which can be empty
		print(self.states)
		if state_vals > 0:  # if the stateful values have some state -> enter the if loop
			ivalues = []
			print("\n\n...Running in Stateful mode...\n\n")
			ikeys = ['dp', 'scale', 'um']
			for istate in self.states:  # istate will be um, scale or dp
				print("Safe sleep -- 20 seconds\n")
				sleep(20)  # safe sleep between processes
				iistate = self.states[istate]
				if iistate != []:  # for each item, check if the state exists
					if iistate[0] == 'pre_import':  # if exists -> is it pre_import state ?
						print("State:", iistate[0])
						# state_values = ["pre_import", image_id, self.img_name, import_task_id]
						print("\n Importing {} from {} to {} \n".format(iistate[2], self.bucket, self.region))
						# if the state is pre_import , verify the task status and if not status, check the image existence
						import_args = {'image_key': istate, 'image_object_name': iistate[2], 'img_id': iistate[1],
						               'task_id': iistate[3], 'state': True}
						print(import_args)
						try:
							pre_i_proc = Process(target=self.import_and_tag_thread,
							                     name='Image Import Process: {}'.format(iistate[2]),
							                     kwargs=import_args)
							import_processes.append(pre_i_proc)
							pre_i_proc.start()
						except Exception as e:
							print("Error: ", e)
							sys.exit(1)
						# img_id = self.import_image(image_object_name=iistate[2], img_id=iistate[1], task_id=iistate[3], state=True)
						# print("Stateful- Import Done"
						# self.tag_image(import_image_id=img_id, img_name=istate)
					elif iistate[0] == 'IDone':  # if exists is it a Idone state ? -> If so, just tag it
						print("Stateful- Import already done... Applying Tags")
						import_args = {'image_key': istate, 'image_object_name': iistate[2], 'img_id': iistate[1],
						               'task_id': iistate[3], 'state': True}
						print(import_args)
						try:
							pre_i_proc = Process(target=self.import_and_tag_thread,
							                     name='Image Import Process: {}'.format(iistate[2]),
							                     kwargs=import_args)
							import_processes.append(pre_i_proc)
							pre_i_proc.start()
						except Exception as e:
							print("Error: ", e)
							sys.exit(1)
					elif iistate[0] == "Done":
						print("Stateful - Done: Nothing to do: just skipping the processing of {}\n".format(istate))
						pass
				elif iistate == []:  # for each item, if this is not an item with some state
					print("No State!")
					if istate == 'dp':
						name = self.dp_name
					elif istate == 'um':
						name = self.um_name
					elif istate == 'scale':
						name = self.scale_lc_name
					print("\n Importing {} from {} to {} \n".format(name, self.bucket, self.region))
					import_args = {'image_key': istate, 'image_object_name': name}
					print(import_args)
					try:
						sfi_proc = Process(target=self.import_and_tag_thread,
						                   name='Image Import Process: {}'.format(name), kwargs=import_args)
						import_processes.append(sfi_proc)
						sfi_proc.start()
					except Exception as e:
						print("Error: ", e)
						sys.exit(1)
					# img_id = self.import_image(image_object_name=name)
					# Tag the imported image
					# self.tag_image(import_image_id=img_id, img_name=istate)

			for proc in import_processes:
				proc.join()
				print("Import process: {} Joined".format(proc.name))
				if proc.exitcode != 0:
					exit_codes.append(proc.name)
				sleep(1)
			if len(exit_codes) != 0:
				print("Failed Processes Found - look for errors or exceptions in the log: {}".format(exit_codes))
				print("Clear the state in the cfg file before running the next ")
				sys.exit(1)
			for i in ikeys:
				print("Clearing State: ", i)
				self.maintain_state(key=i, value=[], lck=self.lock)
		else:  # if the stateful values doesnt have any state -> enter the else loop
			print("-----Stateful section is empty in cfg ------")
			i_processes = []
			for i in image_dict:
				name = image_dict[i]['name']
				print("\n Importing {} from {} to {} \n".format(name, self.bucket, self.region))
				keywords = {'image_key': i, 'image_object_name': name}
				# print("Import Arguments: ", import_args)
				try:
					i_proc = Process(target=self.import_and_tag_thread,
					                 name='Image Import Process: {}'.format(name), kwargs=keywords)
					i_processes.append(i_proc)
					i_proc.start()
					print("{} Started".format(i_proc.name))
				except Exception as e:
					print("Error: ", e)
					sys.exit(1)
				# img_id = self.import_image(image_object_name=name)
				# Tag the imported image
				# self.tag_image(import_image_id=img_id, img_name=i)
			for proc in i_processes:
				proc.join()
				print("Import process: {} Joined".format(proc.name))
				sleep(1)
				if proc.exitcode != 0:
					exit_codes.append(proc.name)
				sleep(1)
			if len(exit_codes) != 0:
				print("Failed Processes Found - look for errors or exceptions in the log: {}".format(exit_codes))
				print("Clear the state in the cfg file before running the next ")
				sys.exit(1)
			ikeys = ['dp', 'scale', 'um']
			for i in ikeys:
				print("Clearing State: ", i)
				self.maintain_state(key=i, value=[], lck=self.lock)
		print("Job Done!")
