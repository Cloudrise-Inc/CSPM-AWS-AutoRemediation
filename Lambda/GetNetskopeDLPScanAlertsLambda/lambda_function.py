# Standard library imports
from datetime import datetime
from io import StringIO
import json
import os
from time import time

# Lambda native imports
import boto3
import botocore

# PyPi imports
import requests

# Other imports
from utils.logger import Logger

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

s3_client = boto3.client("s3")
S3_BUCKET = os.environ['dlp_scan_alert_results_s3_bucket']
tenant_fqdn = os.environ['tenant_fqdn']
PAGE_SIZE = 100
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
secret_arn = os.environ['api_token']
AWS_REGIONS={
  "us-east-1": "US East(N. Virginia)",
  "us-east-2": "US East(Ohio)",
  "us-west-1": "US West(N. California)",
  "us-west-2": "US West(Oregon)"
}


def lambda_handler(event, context):

    token = json.loads(get_secret(secret_arn))['token']
    action_name = event['action']
    policies = event['policies']
    profiles = event['profiles']
    rules = event['rules']

    # get cursor timestamp from s3. Add 1 to it.
    start_time = get_last_timestamp(S3_BUCKET, action_name) + 1
    last_timestamp = start_time 
    
    file_name = f"{tenant_fqdn}.{action_name}.{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    results = StringIO("")
    page = 0
    resp = get_alerts(action_name, token, str(PAGE_SIZE), str(page*PAGE_SIZE), start_time)
    logger.debug(resp)
    count = 0
    while len(resp):
        for item in resp:
            policy = item["policy"]
            profile = item["dlp_profile"]
            rule = item["dlp_rule"]
            # If the current item is in the configured policy, profile or ruleset for this action then add it to the result.
            if policy in policies or profile in profiles or rule in rules:
                logger.info(f"Got matching alert for action: {action_name} on instance: {item['instance']} for resource_id: {item['object_id']} with (policy_name: {item['policy']}, profile_name: {item['dlp_profile']}, rule_name: {item['dlp_rule']})")
                resource_id = f"arn:aws:s3:::{item['file_path']}"
                # Assumes the last field in the instance name is the account id.
                account_id = item["instance"].split('_')[-1]
                results.write(f"{account_id}, {resource_id}, {item['policy']}, {item['dlp_profile']}, {item['dlp_rule']}\n")
                count += 1
                if int(item["timestamp"]) > last_timestamp:
                    last_timestamp = int(item["timestamp"])
        page=page+1
        resp = get_alerts (action_name, token, str(PAGE_SIZE), str(page*PAGE_SIZE), start_time)
        logger.debug(resp)
    
    logger.info(f"Got {count} total alerts for the action {action_name}")

    put_results(results, S3_BUCKET, f"{action_name}/{file_name}")
    put_last_timestamp(S3_BUCKET, action_name, last_timestamp)
  

def get_last_timestamp(bucket, action_name):
    try:
        s3 = boto3.client("s3") 
        object_key = f"{action_name}/last_timestamp_{action_name}.txt"
        object = s3.get_object(Bucket=bucket, Key=object_key)
        timestamp = int(object['Body'].read().strip())

    except botocore.exceptions.ClientError as e:
        logger.debug(f"Could not find timestamp using 1 {e}")
        timestamp = 1
    except KeyError:
        logger.debug("result dictionary invalid.")
        timestamp = 1
    
    return timestamp


def put_last_timestamp(bucket, action_name, timestamp):
    s3 = boto3.client("s3") 
    object_key = f"{action_name}/last_timestamp_{action_name}.txt"
    s3.put_object(Bucket=bucket, Key=object_key, Body=str(timestamp).encode())


def put_results(results, bucket, key):
    if isinstance(results, StringIO):
        results = results.getvalue()
    if isinstance(results, str):
        results = results.encode()
    if len(results) > 0:
        s3 = boto3.client("s3")
        s3.put_object(Bucket=bucket, Key=key, Body=results)


def get_alerts(action_name, token, limit, skip, starttime):
    now = time()
    get_url = f"https://{tenant_fqdn}/api/v1/alerts"
    payload = {"token" : token, 
               "type": "DLP",
               "acked": "false",
               "starttime": starttime,
               "endtime": now,
               "query": "app like 'Amazon Web Services'",
               "limit": limit,
               "skip": skip
               }
    
    logger.info(f"Calling Netskope API for DLP scan alerts for {action_name}" )
    r = requests.get(get_url, params=payload)
    return r.json()['data']


def get_secret(secret_arn):
    
    logger.debug(secret_arn)
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=AWS_REGION
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        response = client.describe_secret(SecretId=secret_arn)
        
        get_secret_value_response = client.get_secret_value(
            SecretId=response['Name']
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
            print(e)
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        secret = get_secret_value_response['SecretString']
    return(secret)

if __name__ == "__main__":
    lambda_handler({
        "action": "label",
        "account_id": "dsfasdfdfdfddkdkd"
    }, None)