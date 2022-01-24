import boto3
import botocore
from datetime import datetime, timezone
import json
import requests
import os
from os import listdir
from os.path import isfile, join
from time import time
from utils.logger import Logger

# Set up  logger
LOG_LEVEL = os.getenv('LOGLEVEL', 'info')
logger = Logger(loglevel=LOG_LEVEL)

# s3_client = boto3.client("s3")
# LOCAL_FILE_SYS = "/tmp"
LOCAL_FILE_SYS = "./tmp"
# S3_BUCKET = os.environ['dlp_scan_alert_results_s3_bucket']
tenant_fqdn = os.environ['tenant_fqdn']
PAGE_SIZE = 100
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
# secret_arn = os.environ['api_token']
AWS_REGIONS={
  "us-east-1": "US East(N. Virginia)",
  "us-east-2": "US East(Ohio)",
  "us-west-1": "US West(N. California)",
  "us-west-2": "US West(Oregon)"
}

def lambda_handler(event, context):
   
    # TODO Filter alerts for action by Policies, profiles, and rules.

    # token = json.loads(get_secret(secret_arn))['token']
    token = "2730ce508a7e12d1dcd00620f5de7cc2"


    action_name = event['action']

    file_name = os.path.expandvars(os.path.join(LOCAL_FILE_SYS, f"{tenant_fqdn}.{action_name}.{datetime.now().strftime('%Y%m%d%H%M%S')}"))
    with open(file_name, "w") as file:
        # TODO: Pull last timestamp from cursor for this action.

        page = 0
        y = 0
        resp = get_status(action_name, token, str(PAGE_SIZE), str(page*PAGE_SIZE))
        logger.debug(resp)
        count = 0
        while len(resp):
            for item in resp:
                resource_id = f"arn:aws:s3:::{item['file_path']}"
                # Assumes the last field in the instance name is the account id.
                account_id = item["instance"].split('_')[-1]
                bucket_id = resource_id.split("/")[0]
                logger.info(f"Got alert for the account {account_id} instance: {item['instance']} resource_id: {resource_id} bucket_id: {bucket_id} policy_name: {item['policy']} profile_name: {item['dlp_profile']} rule_name: {item['dlp_rule']}")
                file.write(f"{account_id}, {resource_id}, {item['policy']}, {item['dlp_profile']}, {item['dlp_rule']}\n")
                count += 1
            page=page+1
            resp = get_status (action_name, token, str(PAGE_SIZE), str(page*PAGE_SIZE))
            logger.debug(resp)
    
    logger.info(f"Got {count} total alerts for the action {action_name}")
    # TODO move temp file to s3 bucket.
    # if y:
    #     files = [f for f in listdir(LOCAL_FILE_SYS) if isfile(join(LOCAL_FILE_SYS, f))]
    #     for f in files:
    #         s3_client.upload_file(LOCAL_FILE_SYS + "/" + f, S3_BUCKET, action_name +'/'+ f)


def get_status(action_name, token, limit, skip, starttime):
    
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