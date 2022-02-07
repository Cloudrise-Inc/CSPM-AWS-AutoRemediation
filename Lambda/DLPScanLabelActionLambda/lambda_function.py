import csv
import json
import logging
import os
import urllib

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import s3fs
from utils.awsapi_helpers import AWSClient, BotoSession


# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'INFO')
LOG_LEVEL = LOG_LEVEL.upper()
logger = logging.getLogger() 
logger.setLevel(logging.getLevelName(LOG_LEVEL))

LAMBDA_ROLE = 'S3DLPLabelActionTargetRole'
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')

# TODO: Some default bucket and Objecttags.
BUCKET_LABEL = os.getenv("BUCKET_LABEL", None)
OBJECT_LABEL = os.getenv("OBJECT_LABEL", None)
LAMBDA_ROLE += '_' + AWS_REGION
BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    },
    region_name=AWS_REGION
)

def lambda_handler(event, context):

    AWS = AWSClient(AWS_PARTITION, AWS_REGION)
    s3 = s3fs.S3FileSystem(anon=False)

    logger.info(json.dumps(event))

    logger.debug(event)
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    input_file = os.path.join(bucket, key)
    
    try:
        inFile = s3.open(input_file, 'r', newline='\n', encoding='utf-8-sig')
        fileReader = csv.reader(inFile)
        for row in fileReader:
            label_artifacts(row)
    except Exception as e:
        logger.error(e)
        logger.error('Error getting object from bucket. Make sure they exist and your bucket is in the same region as this function. '+ input_file)
        raise e

def label_artifacts(row):
    account_id = row[0]
    resource_id = row[1]
    logger.info('Got event: '+account_id+' '+ resource_id)
    bucket, key = extract_bucket_and_key(resource_id)
    if BUCKET_LABEL is not None:
        tags = {"S3DLPScanLabel": BUCKET_LABEL}
        tag_bucket(account_id, LAMBDA_ROLE, bucket, **tags)
    if OBJECT_LABEL is not None:
        tags = {"S3DLPScanLabel": OBJECT_LABEL}
        tag_object(account_id, LAMBDA_ROLE, bucket, key, **tags)
    
    logger.info('Remediation was successfully invoked To label the bucket and resource for' +account_id+' '+ resource_id )


def extract_bucket_and_key(resource_id):
    bucket_key = resource_id.split(":")[-1]
    bucket, key = bucket_key.split("/", 1)
    return bucket, key

def tag_bucket(account_id, role, bucket, **tags):
    # Assume the role to perform on the target.
    sess = BotoSession(account_id, role)
    cls3 = sess.client('s3')
    existing_tags = cls3.get_bucket_tagging(Bucket=bucket)

    # pull Tags out of list in TagSet
    existing_tags = {i['Key']: i['Value'] for i in existing_tags['TagSet']}
    new_tags = {**existing_tags, **tags}

    response = cls3.put_bucket_tagging(Bucket=bucket,
        Tagging={
            'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in new_tags.items()]
        }
    )

    # Return resonse status code is OK
    return response['ResponseMetadata']['HTTPStatusCode'] == 200
 
def tag_object(account_id, role, bucket, key, **tags):
    # Assume the role to perform on the target.
    sess = BotoSession(account_id, role)
    cls3 = sess.client('s3')
    existing_tags = cls3.get_object_tagging(Bucket=bucket, Key=key)

    # pull Tags out of list in TagSet
    existing_tags = {i['Key']: i['Value'] for i in existing_tags['TagSet']}
    new_tags = {**existing_tags, **tags}

    response = cls3.put_object_tagging(Bucket=bucket, Key=key,
        Tagging={
            'TagSet': [{'Key': str(k), 'Value': str(v)} for k, v in new_tags.items()]
        }
    )

    # Return resonse status code is OK
    return response['ResponseMetadata']['HTTPStatusCode'] == 200