"""Helper class for AWS API access"""
###############################################################################
#  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

# *******************************************************************
# Required Modules:
# *******************************************************************

import os
import json
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(
    retries = {
        'max_attempts': 10
    }
)

class AWSClient:
    region = ''
    partition = ''
    CLIENT = {}

    def __init__(self, partition, region):
        self.partition = partition
        self.region = region

    def connect(self, service, region):
        """Connect to AWS api"""

        self.CLIENT[service] = {}
        try:
            self.CLIENT[service][region] = boto3.client(service, region_name=region, config=BOTO_CONFIG)
        except Exception as exc:
            print(exc)
            print('Could not connect to ' + service + ' in region ' + region)
            raise
        else:
            print('Connected to ' + service + ' in region ' + region)

    def whoami(self, region=None):
        """
        get local account info
        """
        if not region:
            region = self.region
        if ('sts' not in self.CLIENT) or ('sts' in self.CLIENT and region not in self.CLIENT['sts']):
            self.connect('sts', region)
        retstuff = self.CLIENT['sts'][region].get_caller_identity()
        return retstuff

    def postit(self, topic, message, region=None):
        """
        Post a message to an SNS topic
        """
        if not region:
            region = self.region
        message_id = 'error'
        topic_account = str(self.whoami(region=self.region).get('Account'))
        topic_arn = 'arn:' + self.partition + ':sns:' + self.region + ':' + topic_account + ':' + topic
        
        if ('sns' not in self.CLIENT) or ('sns' in self.CLIENT and self.region not in self.CLIENT['sns']):
            self.connect('sns', self.region)
        try:
            json_message = json.dumps({"default":json.dumps(message)})
            message_id = self.CLIENT['sns'][self.region].publish(
                TopicArn=topic_arn,
                Message=json_message,
                MessageStructure='json'
            ).get('MessageId', 'error')
        except Exception as e:
            print(e)

        return message_id

class MissingAssumedRole(Exception):
    pass

class BotoSession:
    clientProps = {}
    resourceProps = {}
    STS = None
    partition = None
    session = None
    target = None
    role = None

    def create_session(self):
        self.STS = None
        # Local or remote? Who am I?
        try:
            self.STS = boto3.client('sts', config=BOTO_CONFIG)
            if not self.target:
                self.target = self.STS.get_caller_identity()['Account']
            if self.role == None:
                raise MissingAssumedRole
            remote_account = self.STS.assume_role(
                RoleArn='arn:' + self.partition + ':iam::' + self.target + ':role/' + self.role,
                RoleSessionName="sechub_admin"
            )
            print('kuku1')
            self.session = boto3.session.Session(
                aws_access_key_id=remote_account['Credentials']['AccessKeyId'],
                aws_secret_access_key=remote_account['Credentials']['SecretAccessKey'],
                aws_session_token=remote_account['Credentials']['SessionToken']
            )

            boto3.setup_default_session()
            # return session
        except Exception as e:
            raise e

    def __init__(self, account=None, role=None, partition=None):
        """
        Create a session
        account: None or the target account
        """
        self.target = account
        self.role = role
        self.session = None
        self.partition = os.getenv('AWS_PARTITION', partition)
        self.create_session()

    def client(self, name, **kwargs):

        try:
            self.clientProps[name] = self.session.client(name, config=BOTO_CONFIG, **kwargs)
            return self.clientProps[name]
        except Exception as e:
            raise e

    def resource(self, name, **kwargs):

        try:
            self.resourceProps[name] = self.session.resource(name, config=BOTO_CONFIG, **kwargs)
            return self.resourceProps[name]
        except Exception as e:
            raise e

