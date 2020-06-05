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
#
# AWS S3 Bucket - Operations

# standard library

# 3rd party library

# shieldx library

class S3Bucket(object):
    def __init__(self, s3_client=None, s3_resource=None):
        self.s3_client = s3_client
        self.s3_resource = s3_resource

    def create_bucket(self, bucket_name, location="us-west-1"):
        return self.s3_client.create_bucket(
                   Bucket = bucket_name,
                   CreateBucketConfiguration = {
                       "LocationConstraint": location
                   }
               )

    # Applies for both Create and Update
    def put_bucket_policy(self, bucket_name, bucket_policy):
        return self.s3_client.put_bucket_policy(
                   Bucket = bucket_name,
                   Policy = bucket_policy
               )

    def list_buckets(self):
        return self.s3_client.list_buckets()

    def get_bucket_policy(self, bucket_name):
        return self.s3_client.get_bucket_policy(
                   Bucket = bucket_name,
               )

    def get_bucket_encryption(self, bucket_name):
        return self.s3_client.get_bucket_encryption(
                   Bucket = bucket_name,
               )

    def server_side_encrypt_bucket(self, bucket_name, encryption_config):
        return self.s3_client.put_bucket_encryption(
                   Bucket = bucket_name,
                   ServerSideEncryptionConfiguration = encryption_config
               )
 
    def delete_bucket(self, bucket_name):
        return self.s3_client.delete_bucket(
                   Bucket = bucket_name,
               )

    def upload_small_file(self, filename, bucket_name, key):
        return self.s3_client.upload_file(
                   filename,
                   bucket_name,
                   key
               )

    def upload_large_file(self, filename, bucket_name, key, extra_args, config, callback):

        return self.s3_resource.meta.client.upload_file(
                   filename,
                   bucket_name,
                   key,
                   ExtraArgs = extra_args,
                   Config = config,
                   Callback = callback
               )

    def read_object_from_bucket(self, bucket_name, key):
        return self.s3_client.get_object(
                   Bucket = bucket_name,
                   Key = key
               )

    def version_bucket_files(self, bucket_name, version_config):
        return self.s3_client.put_bucket_versioning(
                   Bucket = bucket_name,
                   VersioningConfiguration = version_config
               )

    def put_lifecycle_policy(self, bucket_name, policy):
        return self.s3_client.put_bucket_lifecycle_configuration(
                   Bucket = bucket_name,
                   LifecycleConfiguration = policy
               )
