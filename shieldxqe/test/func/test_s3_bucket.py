import pytest
import json
import os
import time
import threading

# shieldx - sxapi library
from sxswagger.aws.s3_bucket import S3Bucket

from boto3.s3.transfer import TransferConfig

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name, location", [
        ("juan-s3-bucket-2020", "us-west-1"),
    ]
)
def test_s3_create_bucket(s3_client, bucket_name, location, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    #bucket_name = "juan-s3-bucket-2020"
    #location = "us-west-1"

    response = s3_bucket.create_bucket(bucket_name, location)
    shieldx_logger.info("Create Bucket Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_create_bucket_policy(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    resource = "{}:{}:{}:::{}/*".format("arn", "aws", "s3", bucket_name)
    bucket_policy_dict = {
        "Version": "2012-10-17",
        "Statement" : [
            {
                "Sid": "AddPerm",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:*"],
                "Resource": resource
            },
        ]
    }

    bucket_policy = json.dumps(bucket_policy_dict)

    response = s3_bucket.put_bucket_policy(bucket_name, bucket_policy)
    shieldx_logger.info("Put Bucket Policy Response: {}".format(response))

@pytest.mark.aws_s3
def test_s3_list_buckets(s3_client, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    buckets = s3_bucket.list_buckets()

    for bucket in buckets:
        shieldx_logger.info("Bucket: {}".format(bucket))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_get_bucket_policy(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    bucket_policy = s3_bucket.get_bucket_policy(bucket_name)
    shieldx_logger.info("Bucket Policy: {}".format(bucket_policy))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_get_bucket_encryption_xfail(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    try:
        bucket_encryption = s3_bucket.get_bucket_encryption(bucket_name)

        shieldx_logger.info("Bucket Encryption: {}".format(bucket_encryption))
    except Exception as e:
        shieldx_logger.error("Bucket Encryption Error: {}".format(e))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_update_bucket_policy(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    resource = "{}:{}:{}:::{}/*".format("arn", "aws", "s3", bucket_name)
    bucket_policy_dict = {
        "Version": "2012-10-17",
        "Statement" : [
            {
                "Sid": "AddPerm",
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "s3:DeleteObject",
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": resource
            },
        ]
    }

    bucket_policy = json.dumps(bucket_policy_dict)

    # Create and Update use the same call
    response = s3_bucket.put_bucket_policy(bucket_name, bucket_policy)
    shieldx_logger.info("Update Bucket Policy Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_server_side_bucket_encrypt_bucket(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    resource = "{}:{}:{}:::{}/*".format("arn", "aws", "s3", bucket_name)
    encryption_config = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }
        ]
    }

    # Server Side Bucket Encryption
    response = s3_bucket.server_side_encrypt_bucket(bucket_name, encryption_config)
    shieldx_logger.info("Server Side Encryption Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_get_bucket_encryption_xpass(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    try:
        bucket_encryption = s3_bucket.get_bucket_encryption(bucket_name)

        shieldx_logger.info("Bucket Encryption: {}".format(bucket_encryption))
    except Exception as e:
        shieldx_logger.error("Bucket Encryption Error: {}".format(e))

@pytest.mark.aws_s3
@pytest.mark.parametrize(
    "bucket_name, small_file", [
        ("juan-s3-bucket-2020", "file1k.txt"),
    ]
)
def test_s3_upload_small_file(
    s3_client, bucket_name,
    datadir, small_file,
    shieldx_constants, shieldx_logger
):
    s3_bucket = S3Bucket(s3_client=s3_client)

    resolved_small_file = str((datadir/small_file).resolve())

    # upload file, key = small_file
    response = s3_bucket.upload_small_file(resolved_small_file, bucket_name, small_file)
    shieldx_logger.info("Upload Small File Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize(
    "bucket_name, large_file", [
        ("juan-s3-bucket-2020", "aburame.tar"),
    ]
)
def test_s3_upload_large_file(
    s3_resource, bucket_name,
    datadir, large_file,
    shieldx_constants, shieldx_logger
):
    s3_bucket = S3Bucket(s3_resource=s3_resource)

    resolved_large_file = str((datadir/large_file).resolve())
    key_path = "{}/{}".format("multipart_files", large_file)

    config = TransferConfig(
                 multipart_threshold = 1024 * 25,
                 max_concurrency = 10,
                 multipart_chunksize = 1024 * 25,
                 use_threads = True
             )

    extra_args = {
                     "ACL": "public-read",
                     "ContentType": "application/tar"
                 }

    progress_logger = ProgressPercentage(resolved_large_file, shieldx_logger)

    # upload file
    response = s3_bucket.upload_large_file(
                   resolved_large_file,
                   bucket_name,
                   key_path,
                   extra_args,
                   config,
                   progress_logger
               )

    shieldx_logger.info("Upload Large File Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize(
    "bucket_name, small_file", [
        ("juan-s3-bucket-2020", "file1k.txt"),
    ]
)
def test_s3_read_objects(
    s3_client, bucket_name,
    datadir, small_file,
    shieldx_constants, shieldx_logger
):
    s3_bucket = S3Bucket(s3_client=s3_client)

    # upload file, key = small_file
    response = s3_bucket.read_object_from_bucket(bucket_name, small_file)
    shieldx_logger.info("Read Object From Bucket: {}".format(response))

    # Download it and write in to local directory
    # downloaded_file = "dl1_" + "small_file"
    # resolved_small_file =  + str((datadir/downloaded_file).resolve())

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_version_bucket(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    # Enable Version Control
    version_config = {
        "Status": "Enabled"
    }

    response = s3_bucket.version_bucket_files(bucket_name, version_config)
    shieldx_logger.info("Version Bucket Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize(
    "bucket_name, small_file", [
        ("juan-s3-bucket-2020", "edit1_file1k.txt"),
    ]
)
def test_s3_upload_small_file_new_version(
    s3_client, bucket_name,
    datadir, small_file,
    shieldx_constants, shieldx_logger
):
    s3_bucket = S3Bucket(s3_client=s3_client)

    resolved_small_file = str((datadir/small_file).resolve())

    key = small_file.split("_")[1]

    # upload file, key = small_file
    response = s3_bucket.upload_small_file(resolved_small_file, bucket_name, key)
    shieldx_logger.info("Upload Small File Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_put_lifecycle_policy(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    lifecycle_policy = {
        "Rules": [
            {
                "ID": "Move small text files to Glacier",
                "Status": "Enabled",
                "Prefix": "file1k",
                "Transitions": [
                    {
                        "Date": "2020-05-21T00:00:00.000Z",
                        "StorageClass": "GLACIER"
                    }
                ]
            },
            {
                "ID": "Move old versions to Glacier",
                "Status": "Enabled",
                "Prefix": "",
                "NoncurrentVersionTransitions": [
                    {
                        "NoncurrentDays": 2,
                        "StorageClass": "GLACIER"
                    }
                ]
            }
        ]
    }
    # Put lifecycle policy in place, delete after n days or put in glacier storage
    response = s3_bucket.put_lifecycle_policy(bucket_name, lifecycle_policy)
    shieldx_logger.info("Put Lifecycle Policy Response: {}".format(response))

@pytest.mark.aws_s3
@pytest.mark.parametrize("bucket_name", [
        ("juan-s3-bucket-2020"),
    ]
)
def test_s3_delete_bucket(s3_client, bucket_name, shieldx_constants, shieldx_logger):
    s3_bucket = S3Bucket(s3_client=s3_client)

    # Delete Bucket
    response = s3_bucket.delete_bucket(bucket_name)
    shieldx_logger.info("Delete Bucket Response: {}".format(response))

class ProgressPercentage(object):
    def __init__(self, filename, shieldx_logger):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._progress = 0
        self._lock = threading.Lock()
        self.logger = shieldx_logger

    def __call__(self, bytes_amount):
        with self._lock:
            self._progress += bytes_amount

            percentage = (self._progress / self._size) * 100

            self.logger.info("{} {}/{} ({})".format(self._filename, self._progress, self._size, percentage))

# Sample run
#  python3 -m pytest shieldxqe/test/func/test_s3_bucket.py -v --setup-show -s --shieldx --branch SxRel2.1 -m aws_s3
