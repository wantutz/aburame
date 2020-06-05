from __future__ import print_function
import boto3
from configobj import ConfigObj as CO
from botocore.exceptions import ClientError
import sys
from time import sleep
import json

# Author: Vamsi
# Date: 5/3/2018
# Date Modified: 3/8/2019


class ConfigService(object):
	def __init__(self):
		self.cfg_file = '../Configs/aws_configservice.cfg'
		self.config = CO(infile=self.cfg_file)
		self.access_key = self.config['ACCESS_KEY']
		self.secret_key = self.config['SECRET_KEY']
		self.region = self.config['REGION']
		self.account_id = self.config['AWS_ACCOUNT_ID']
		self.role_name = self.config['ROLE_POLICY']['ROLE_NAME']
		self.policy_name = self.config['ROLE_POLICY']['POLICY_NAME']
		self.s3_bucket_name = self.config['S3']['BUCKET_NAME']
		self.sns_topic_name = self.config['SNS']['TOPIC_NAME']
		self.snsTopicARN = None
		# set the sns use_existing_topic to True or False based on the config
		self.use_existing_topic = True if self.config['SNS']['USE_EXISTING'].lower() == 'yes' else False
		self.config_recorder_name = self.config['CONFIG_RECORDER']['NAME']
		self.delivery_channel_name = self.config['DELIVERY_CHANNEL']['NAME']
		self.sqs_name = self.config['SQS']['QUEUE_NAME']
		self.config_con = boto3.client('config', region_name=self.region, aws_access_key_id=self.access_key,
		                               aws_secret_access_key=self.secret_key)
		self.iam_con = boto3.client('iam', region_name=self.region, aws_access_key_id=self.access_key,
		                            aws_secret_access_key=self.secret_key)
		self.s3_con = boto3.client('s3', region_name=self.region, aws_access_key_id=self.access_key,
		                           aws_secret_access_key=self.secret_key)
		self.sns_con = boto3.client('sns', region_name=self.region, aws_access_key_id=self.access_key,
		                            aws_secret_access_key=self.secret_key)
		self.sqs_con = boto3.client('sqs', region_name=self.region, aws_access_key_id=self.access_key,
		                            aws_secret_access_key=self.secret_key)

	def create_s3_bucket(self, bucket_name=None):
		"""
		check: if bucket exists, skip creation; else create bucket
		:return:
		"""
		if bucket_name is None:
			bucket_name = self.s3_bucket_name
		print('\n------------- Creating S3 Bucket --------------\n')
		try:
			check_bucket = self.s3_con.head_bucket(Bucket=bucket_name)
		except ClientError as e:
			# self.logger.warn("Bucket with this name does not exist ", e)
			print("Bucket with this name does not exist ", e)
			# self.logger.info("Creating the S3 bucket: ", self.bucket)
			print("Creating the S3 bucket: ", bucket_name)
			create_resp = self.s3_con.create_bucket(ACL='private', Bucket=bucket_name,
			                                        CreateBucketConfiguration={'LocationConstraint': self.region})
			r = create_resp['ResponseMetadata']
			status = r['HTTPStatusCode']
			if status == 200:
				# self.logger.info("Bucket Created Successfully at {}".format(create_resp['Location']))
				print("Bucket Created Successfully at {}".format(create_resp['Location']))
				# print(create_resp
				return r['HostId']
			else:
				print("Creation of Bucket Failed", r['HTTPStatusCode'])
				print(create_resp)
				sys.exit(1)
		else:
			print(check_bucket)
			print("Bucket exists! Skipped Bucket Creation")

	def delete_s3_bucket(self, bucket_name=None):
		if bucket_name is None:
			bucket_name = self.s3_bucket_name
		if self.delete_s3_objects(bucket_name=bucket_name):
			sleep(5)
			try:
				print('\n------------- Deleting S3 Bucket --------------\n')
				delete_bucket = self.s3_con.delete_bucket(Bucket=bucket_name)
			except Exception as delete_bucket_err:
				print("Error while deleting the bucket {}: {}".format(bucket_name, delete_bucket_err))
				if 'NoSuchBucket' in delete_bucket_err.response['Error']['Code']:
					print("Bucket not found: Already Deleted: Ignoring error and doing safe exit")
					return None
				else:
					sys.exit(1)
			else:
				print("Bucket: {} got deleted successfully\n".format(bucket_name))
				print(delete_bucket)
		else:
			print("Failed to deleted S3 Objects")
			sys.exit(1)

	def delete_s3_objects(self, bucket_name=None):
		if bucket_name is None:
			bucket_name = self.s3_bucket_name
		print('\n------------- Deleting S3 Bucket Objects --------------\n')
		try:
			objects = self.s3_con.list_objects(Bucket=bucket_name)
		except Exception as list_obj_err:
			print("Error while fetching the list objects of the bucket {}: {}\n".format(bucket_name, list_obj_err))
			if 'NoSuchBucket' in list_obj_err.response['Error']['Code']:
				print("Bucket not found: Already Deleted: Ignoring error and doing safe exit")
				return None
			else:
				sys.exit(1)
		else:
			print("Got the Object list")
			if 'Contents' in objects.keys():
				object_list = [{'Key': obj['Key']} for obj in objects['Contents']]
			else:
				print("No Contents... Nothing to delete in Objects")
				return None
		try:
			delete_objects = self.s3_con.delete_objects(Bucket=bucket_name, Delete={'Objects': object_list})
		except Exception as delete_obj_err:
			print("Error while deleting the Objects from the bucket {}: {}".format(bucket_name, delete_obj_err))
			sys.exit(1)
		else:
			print("All the Objects in the bucket {} got deleted successfully\n".format(bucket_name))
			print(delete_objects)
			return True

	def create_sns_topic(self, topic_name=None, use_existing=None):
		"""
		This action is idempotent, so if the topic with the specified name exists, that topic's ARN is returned without creating a new topic.
		 However, I verify the topic existence and return the topic_arn; can throw error if use_existing is set to False

		:param topic_name: None
		:param use_existing:True by default (self.use_existing_topic
		:return: topic_arn
		"""
		print('\n-------------- Creating SNS Topic ------------ \n')
		if topic_name is None:
			topic_name = self.sns_topic_name
		if use_existing is None:
			use_existing = self.use_existing_topic
		print("Verifying whether the topic with this name: {}, already exists or not...".format(self.sns_topic_name))
		topic_arn = self.get_topic_arn(topic_name=topic_name)
		if topic_arn is not None:
			if use_existing is True:
				print("Topic already exists: use_existing param is set to True...returning the existing Topic_Arn")
				return topic_arn
			else:
				print("Topic already exists: use_existing param is set to false...exiting out")
				sys.exit(1)
		try:
			sns_topic = self.sns_con.create_topic(Name=topic_name)
		except Exception as sns_error:
			print("Unable to create the SNS topic: {}. \nError: \t{}".format(topic_name, sns_error))
			sys.exit(1)
		else:
			if sns_topic['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Query successful")
				print("SNS Topic: {} got created successfully\n".format(topic_name))
				return sns_topic['TopicArn']
			else:
				print("SNS topic creation unsuccessful : ", sns_topic)
				sys.exit(1)

	def delete_sns_topic(self, topic_name=None):
		"""
		get the topic_name and then delete the topic: will delete every thing associated with the topic
		:param topic_name:
		:return: None
		"""
		print('\n ------ Deleting SNS Topic ------ \n')
		if topic_name is None:
			topic_name = self.sns_topic_name
		topic_arn = self.get_topic_arn(topic_name=topic_name)
		if topic_arn is None:
			print("Topic doesnt exist")
			return None
		try:
			topic_delete = self.sns_con.delete_topic(TopicArn=topic_arn)
		except Exception as e:
			print("Error while deletion of topic: ", e)
			sys.exit(1)
		else:
			print("Topic Deleted successfully {}\n".format(topic_delete))
			return None

	def list_sns_topics(self):
		"""
		list limit 100 topics, return dict contains NextToken string, with which we can dig further by providing it as arg

		:return: dict(Topics = [{TOPIC_ARN},... ], NextToken='string)
		"""
		print("listing the first 100 SNS topics: ")
		try:
			topics = self.sns_con.list_topics()
			if topics['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Topic Query Request Success")
			else:
				print("topics: ", topics)
				sys.exit(1)
		except Exception as topic_list_err:
			print("Got exception: ", topic_list_err)
		else:
			return topics['Topics']

	def get_topic_subscription_arn(self, topic_arn):
		print("Getting the subscription associated with the Topic\n")
		if topic_arn is None:
			print("No Subscriptions available for the topic_arn: None")
			return None
		try:
			topic_subs = self.sns_con.list_subscriptions_by_topic(
				TopicArn=topic_arn)
		except Exception as e:
			print("Error listing subscriptions for the topic_arn: {}: ".format(topic_arn, e))
			sys.exit(1)
		else:
			print(topic_subs)
			if topic_subs['Subscriptions'] == list():
				print("Subscriptions are empty... can not fetch the subscription ARN")
				return None
			print("Got the ARN for the subscription")
			return topic_subs['Subscriptions'][0]['SubscriptionArn']

	def get_topic_arn(self, topic_name=None):
		"""
		:param topic_name:
		:return: topic_arn -  if found
		:return: None -  if not found
		"""
		print("\nGetting ARN for the topic..")
		if self.snsTopicARN is not None:
			return self.snsTopicARN
		if topic_name is None:
			topic_name = self.sns_topic_name
		topic_arn_dict = self.list_sns_topics()
		for topic_arn in topic_arn_dict:
			if topic_name in topic_arn['TopicArn']:
				if topic_arn['TopicArn'].split(':')[-1] == topic_name:
					print("Found the topic ARN\n")
					return topic_arn['TopicArn']
		print("\nUnable to find the topic ARN for the topic : {}".format(topic_name))
		return None

	# need to be called after the SQS creation
	def subscribe_sns_topic(self, sns_topic_arn, sqs_queue_arn):
		try:
			subscription = self.sns_con.subscribe(TopicArn=sns_topic_arn, Protocol='sqs', Endpoint=sqs_queue_arn)
		except Exception as sub_err:
			print("SNS Topic Subscription Error: ", sub_err)
			sys.exit(1)
		else:
			print("SNS Topic: {} subscribed to endpoint SQS Queue: {} successfully\n".format(self.sns_topic_name,
			                                                                                 self.sqs_name))
			return subscription['SubscriptionArn']

	def unsubscribe_sns_topic(self):
		topic_arn = self.get_topic_arn()
		subscription_arn = self.get_topic_subscription_arn(topic_arn=topic_arn)
		if topic_arn is None:
			print("Topic doesnt exist")
			return None
		if subscription_arn is None:
			print("Nothing to Un-subscribe")
			return None
		try:
			delete_subscription = self.sns_con.unsubscribe(SubscriptionArn=subscription_arn)
		except Exception as unsub_err:
			print("Error Unsubscribing SNS Topic: ", unsub_err)
			sys.exit(1)
		else:
			print("Unsubscribed to the SNS topic", self.sns_topic_name)
			print(delete_subscription)

	def create_policy(self):
		print("\n-------------- Policy Creation ---------------\n")
		topic_arn = self.get_topic_arn()
		if topic_arn is None:
			sys.exit(1)
		config_policy = {"Version": "2012-10-17", "Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3:PutObject*"],
				"Resource": ["arn:aws:s3:::{}/AWSLogs/{}/*".format(self.s3_bucket_name, self.account_id)],
				"Condition": {"StringLike": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
			{
				"Effect": "Allow",
				"Action": ["s3:GetBucketAcl"],
				"Resource": "arn:aws:s3:::{}".format(self.s3_bucket_name)},
			{
				"Effect": "Allow",
				"Action": "sns:Publish",
				"Resource": "{}".format(topic_arn)}
		]}
		p_arn = 'arn:aws:iam::{}:policy/{}'.format(self.account_id, self.policy_name)
		print("Verifying the existence of the policy")
		try:
			check_policy_resp = self.iam_con.get_policy(PolicyArn=p_arn)
			print("Policy Exists: \n", check_policy_resp)
		except Exception as e:
			# no policy: lets create policy
			print("Policy Doesnt exist")
			print(e)
			print("Creating new policy ... \n")
			policy_resp = self.iam_con.create_policy(PolicyName=self.policy_name,
			                                         PolicyDocument=json.dumps(config_policy))
			if policy_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Policy Created Succeessfully! \n PolicyId: ", policy_resp['Policy']['PolicyId'])
				print("Creating a Role and Attaching it to the created Policy: {}".format(
					policy_resp['Policy']['PolicyName']))
				arn = policy_resp['Policy']['Arn']
				return arn
			else:
				print("Failed to create policy: ", policy_resp)
				sys.exit(1)

		else:
			arn = check_policy_resp['Policy']['Arn']
			print("Customer Managed Policy Creation Successful\n")
			return arn

	def create_role(self):
		"""
		https://docs.aws.amazon.com/config/latest/developerguide/iamrole-permissions.html
		:return:
		"""
		print("\n-------------- Creating Role ---------------\n")
		trust_policy = {"Version": "2012-10-17",
		                "Statement": [{"Sid": "", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"},
		                               "Action": "sts:AssumeRole"}]}
		try:
			print("check if the role being created already exists")
			role = self.iam_con.get_role(RoleName=self.role_name)
			print("The Role already exists: ", role)
			return role['Role']['Arn']
		except Exception as role_err:
			# if it doesnt exist: lets create one
			print("Unable to get the Role: ", role_err)
			try:
				# create role
				print("Creating Role")
				role_resp = self.iam_con.create_role(AssumeRolePolicyDocument=json.dumps(trust_policy),
				                                     Path='/', RoleName=self.role_name)
				print("Role Created {}".format(self.role_name))
			except Exception as e:
				# got error while creating the role: exit
				print("Error while dealing with Roles: ", e)
				sys.exit(1)
			else:
				print(role_resp)
				# if role creation successful
				if role_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
					print("\n Role Creation Successful\n")
					return role_resp['Role']['Arn']
				else:
					print("Failed to create the Role: {}\n".format(self.role_name))

	def attach_policies_to_role(self):
		policy_arn = self.create_policy()
		# policy arns for S3 full access, AWS config Role, SNS Full Access
		managed_policies = [policy_arn, 'arn:aws:iam::aws:policy/AmazonS3FullAccess',
		                    'arn:aws:iam::aws:policy/service-role/AWSConfigRole',
		                    'arn:aws:iam::aws:policy/AmazonSNSFullAccess']
		for policy in managed_policies:
			try:
				print("\nAttaching policy : {} to the role: {}".format(policy, self.role_name))
				attach_policy = self.iam_con.attach_role_policy(PolicyArn=policy, RoleName=self.role_name)
				sleep(5)
			except Exception as attach_error:
				print("Unable to attach policy_arn: {} to the role: {}".format(policy, self.role_name))
				print("Error: ", attach_error)
				sys.exit(1)
		print("All managed policies got attached to the role\n")

	def create_config_recorder(self, role_arn, name=None):
		print("\n-------------- Creating ConfigRecorder ---------------\n")
		if name is None:
			name = self.config_recorder_name
		try:
			config_recorder = self.config_con.put_configuration_recorder(ConfigurationRecorder={
				'name': name, 'roleARN': role_arn, 'recordingGroup': {
					'resourceTypes': [
						"AWS::EC2::EIP", "AWS::EC2::Host", "AWS::EC2::Instance", "AWS::EC2::NetworkInterface",
						"AWS::EC2::RouteTable", "AWS::EC2::SecurityGroup", "AWS::EC2::Subnet", "AWS::EC2::Volume",
						"AWS::EC2::VPC", "AWS::ElasticLoadBalancingV2::LoadBalancer",
						"AWS::ElasticLoadBalancing::LoadBalancer"]
				}})
		except Exception as cr_error:
			print("ConfigRecorder creation Error: ", cr_error)
			sys.exit(1)
		else:
			print(config_recorder)
			if config_recorder['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("ConfigRecorder created successfully\n")
			else:
				print("Failed to create the Configuration Recorder\n")

	def get_existing_delivery_channels(self):
		try:
			response = self.config_con.describe_delivery_channels()
		except Exception as e:
			print("Exception while fetching the list of delivery channels")
		else:
			if response['DeliveryChannels'] == list():
				print("No delivery channels are existing in this region")
				return None
			else:
				r = response['DeliveryChannels']
				print("Delivery Channel: {} already exists in this region".format(r))
				self.snsTopicARN = r[0]['snsTopicARN'].encode()
				self.s3_bucket_name = r[0]['s3BucketName'].encode()
				return r

	def create_delivery_channel(self, name=None):
		sns_topic_arn = self.get_topic_arn(topic_name=self.sns_topic_name)
		if sns_topic_arn is None:
			print("Delivery Channel: Unable to get the SNS Topic ARN")
			sys.exit(1)
		if name is None:
			name = self.delivery_channel_name
		print("\n-------------- Creating Delivery Channel ---------------\n")
		try:
			response = self.config_con.put_delivery_channel(DeliveryChannel={
				'name': name,
				's3BucketName': self.s3_bucket_name,
				'snsTopicARN': sns_topic_arn
			})
		except Exception as delivery_err:
			print("Delivery Channel Creation Error: ", delivery_err)
			if 'MaxNumberOfDeliveryChannelsExceededException' in delivery_err:
				print("Reached the max limit for the creation of delivery channels")
				# I should never hit this case - since I do a check for existing delivery channels
			sys.exit(1)
		else:
			if response['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Delivery Channel creation successful\n")
			else:
				print("Delivery Channel Creation Unsuccessful\n")

	def delete_config_recorder(self):
		print("\n------------- Deleting Configuration Recorder -------------\n")
		try:
			delete_cr = self.config_con.delete_configuration_recorder(
				ConfigurationRecorderName=self.config_recorder_name
			)
		except Exception as delete_cr_error:
			print("Exception in Delete Config Recorder: {}\n".format(delete_cr_error))
			if 'NoSuchConfigurationRecorderException' in delete_cr_error.response['Error']['Code']:
				print("Config Recorder not found or already deleted... \ncontinuing to next step")
			else:
				sys.exit(1)
		else:
			print(delete_cr)
			if delete_cr['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Delete Configuration Recorder Successful\n")
			else:
				print("Failed to delete the Configuration Recorder\n")
				sys.exit(1)

	def delete_delivery_channel(self):
		print("\n------------- Deleting Delivery Channel -------------\n")
		try:
			delete_dc = self.config_con.delete_delivery_channel(
				DeliveryChannelName=self.delivery_channel_name)
		except Exception as delete_dc_error:
			print("Exception in Delete Delivery Channel operation: ", delete_dc_error)
		else:
			print(delete_dc)
			if delete_dc['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Delete Delivery Channel Successful\n")
			else:
				print("Unable to delete the Delivery Channel\n")
				sys.exit(1)

	def start_configuration_recorder(self):
		try:
			print("\n-------------- Starting Configuration Recorder ---------------\n")
			start_config = self.config_con.start_configuration_recorder(
				ConfigurationRecorderName=self.config_recorder_name
			)
		except Exception as start_config_err:
			print("Start Configuration Error: ", start_config_err)
		else:
			print(start_config)
			if start_config['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Configuration Recorder started successfully\n")
			else:
				print("Unable to Start the Configuration Recorder")
				sys.exit(1)

	def stop_configuration_recorder(self):
		try:
			print("\n-------------- Stopping Configuration Recorder ---------------\n")
			stop_config = self.config_con.stop_configuration_recorder(
				ConfigurationRecorderName=self.config_recorder_name)
		except Exception as stop_config_err:
			print("Exception in Stop Configuration Recorder Operation: ", stop_config_err)
		else:
			print(stop_config)
			if stop_config['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Configuration Recorder stopped successfully\n")
			else:
				print("Unable to stop the configuration Recorder")
				sys.exit(1)

	def create_sqs_queue(self, queue_name=None):
		print("\n-------------- SQS Queue Creation ---------------\n")
		queue_policy_id = self.sqs_name+'Policy'
		queue_policy = {
		  "Version": "2012-10-17",
		  "Id": queue_policy_id,
		  "Statement": [{
		      "Sid": "Allow-SendMessage-To-Queue-From-All-Account-SNS-Topics",
		      "Effect": "Allow",
		      "Principal": {"AWS": "*"},
		      "Action": "sqs:SendMessage",
		      "Resource": "*",
		      "Condition": {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:*:{}:*".format(self.account_id)}}}]}
		if queue_name is None:
			queue_name = self.sqs_name
		try:
			sqs_queue = self.sqs_con.create_queue(QueueName=queue_name, Attributes={
				'Policy': json.dumps(queue_policy),
				'ReceiveMessageWaitTimeSeconds': '20'
			})
		except Exception as sqs_err:
			print("SQS Queue Creation Error: ", sqs_err)
			sys.exit(1)
		else:
			print(sqs_queue)
			print("SQS Queue creation is successful\n")
			return sqs_queue['QueueUrl']

	def get_sqs_queue_url(self, queue_name=None, account_id=None):
		if queue_name is None:
			queue_name = self.sqs_name
		if account_id is None:
			account_id = self.account_id
		try:
			queue_url = self.sqs_con.get_queue_url(QueueName=queue_name, QueueOwnerAWSAccountId=account_id)
		except Exception as queue_err:
			if '(AWS.SimpleQueueService.NonExistentQueue)' in queue_err:
				print("{} doesnt exist".format(queue_name))
			else:
				print("Exception while fetching the queue_url for the queue {}: {}".format(queue_name, queue_err))
			return None
		else:
			print("Got the QueueUrl for the queue {}".format(queue_name))
			return queue_url['QueueUrl']

	def delete_sqs_queue(self, queue_name=None):
		print("\n-------------- Deleting SQS Queue ---------------\n")
		if queue_name is None:
			queue_name = self.sqs_name
		queue_url = self.get_sqs_queue_url(queue_name=queue_name)
		if queue_url is None:
			print("Nothing to delete in a None type Queue URL\n")
			return None
		try:
			queue_delete = self.sqs_con.delete_queue(QueueUrl=queue_url)
			# deletion of the queue takes up to 60 seconds
			sleep(60)
		except Exception as queue_err:
			print("Queue Deletion Error: ", queue_err)
		else:
			if queue_delete['ResponseMetadata']['HTTPStatusCode'] == 200:
				print("Queue Deleted Successfully\n")
				print(queue_delete)
			else:
				print("Queue Delete Unsuccessful\n")
				print(queue_delete)
				sys.exit(1)

	def get_sqs_queue_list(self, queue_name_prefix=None):
		try:
			print("Getting the list of the SQS Queues (max 1000) ")
			queues = self.sqs_con.list_queues(QueueNamePrefix=queue_name_prefix)
		except Exception as err:
			print("Error getting the list of the SQS Queues", err)
			sys.exit(1)
		else:
			print("Got the SQS Queue list")
			return queues['QueueUrls']

	def get_sqs_queue_arn(self, queue_url):
		try:
			print("Fetching the SQS Queue ARN")
			queue_arn = self.sqs_con.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])
		except Exception as err:
			print("Error while fetching ARN of the Queue", err)
			sys.exit(1)
		else:
			print("Got the SQS Queue ARN", queue_arn)
			return queue_arn['Attributes']['QueueArn']

	def receive_message_on_sqs_queue(self, queue_url):
		print("\n------------- Get Message on the End Point: SQS from SNS -------------\n")
		try:
			message = self.sqs_con.receive_message(QueueUrl=queue_url, AttributeNames=['All'])
		except Exception as e:
			print("Error receiving the message on SQS queue: ", e)
		else:
			print("Got Message: ")
			print(message)
			print("\nEnd of the message")

	def create_discovery_setup(self):
		role_arn = self.create_role()
		topic_arn = self.create_sns_topic()
		self.attach_policies_to_role()
		r = self.get_existing_delivery_channels()
		self.create_config_recorder(role_arn=role_arn)
		if r is not None:
			topic_arn = self.get_topic_arn()
		else:
			self.create_s3_bucket()
			topic_arn = self.create_sns_topic()
			self.create_delivery_channel()
		# role_arn = self.create_role()
		# self.attach_policies_to_role()  # policy gets created here and then attached to the role
		# self.create_config_recorder(role_arn=role_arn)
		queue_url = self.create_sqs_queue()
		queue_arn = self.get_sqs_queue_arn(queue_url=queue_url)
		self.subscribe_sns_topic(sns_topic_arn=topic_arn, sqs_queue_arn=queue_arn)
		self.receive_message_on_sqs_queue(queue_url=queue_url)
		self.start_configuration_recorder()

	def clean_discovery_setup(self):
		print("Cleaning UP the Continuous Discovery Environment Setup\n")
		self.delete_s3_bucket()  # deletes all the objects in the bucket and the bucket
		self.unsubscribe_sns_topic()
		self.delete_sns_topic()
		# roles will stay - not deleting them intentionally
		self.stop_configuration_recorder()
		self.delete_delivery_channel()  # delete the delivery channel before the config recorder
		self.delete_config_recorder()
		self.delete_sqs_queue()


if __name__ == '__main__':
	self = ConfigService()
	if len(sys.argv) == 2:
		print("\n------------- Continuous Discovery Environment Setup or Cleanup Script ------------\n")
		if sys.argv[1].lower() == 'create':
			self.create_discovery_setup()
		elif sys.argv[1].lower() == 'clean':
			self.clean_discovery_setup()
		else:
			print("Argument should be any one of these --> create or clean")
			print("Argument provided by the user --> {}".format(sys.argv[1]))
	else:
		print("Error Missing Arguments: Please provide arguments to create or clean up the setup -> create or clean\n")
