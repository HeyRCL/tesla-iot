'''
Follow these steps to configure the webhook in Slack:

  1. Navigate to https://<your-team-domain>.slack.com/services/new

  2. Search for and select "Incoming WebHooks".

  3. Choose the default channel where messages will be sent and click "Add Incoming WebHooks Integration".

  4. Copy the webhook URL from the setup instructions and use it in the next section.


Follow these steps to encrypt your Slack hook URL for use in this function:

  1. Create a KMS key - http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html.

  2. Encrypt the event collector token using the AWS CLI.
     $ aws kms encrypt --key-id alias/<KMS key name> --plaintext "<SLACK_HOOK_URL>"

     Note: You must exclude the protocol from the URL (e.g. "hooks.slack.com/services/abc123").

  3. Copy the base-64 encoded, encrypted key (CiphertextBlob) to the ENCRYPTED_HOOK_URL variable.

  4. Give your function's role permission for the kms:Decrypt action.
     Example:

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1443036478000",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "arn:aws:kms:us-east-1:189335491223:key/28989805-3d5d-475f-b65d-50a8568ff566"
            ]
        }
    ]
}

Note that you also need your specific vehicle ID, the reason for hardcoding this is because on the IoT
device you can't really deconflict having multiple vehicles in your account.. to obtain this ID you 
need to make a service call to the API to get your vehicle data. 
Use this: http://docs.timdorr.apiary.io/#
'''
from __future__ import print_function

import boto3
import json
import logging


from base64 import b64decode
from urllib2 import Request, urlopen, URLError, HTTPError
from urllib import urlencode

ENCRYPTED_HOOK_URL = '<YOUR ENCRYPTED HOOK HERE>' 
SLACK_CHANNEL = '#general'  # Enter the Slack channel to send a message to

HOOK_URL = "https://" + boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def getTeslaInfo():
    # Tesla's secrets, may change some day
    client_id = "e4a9949fcfa04068f59abb5a658f2bac0a3428e4652315490b659d5ab3f35a9e"
    client_secret = "c75f14bbadc8bee3a7594412c31416f8300256d7668ea7e6e7f06727bfb9d220"
    oauth = {
		  'grant_type' : 'password',
		  'client_id' : client_id,
		  'client_secret' : client_secret,
		  'email' : '<your tesla account email>',
		  'password' : '<your tesla account pw>' 
    }
    # Note that the above includes your secrets
    req = Request("https://owner-api.teslamotors.com/oauth/token", urlencode(oauth)) 
    resp = urlopen(req)
    auth = json.loads(resp.read())
    access_token = auth['access_token']
    vehicle_req = Request("https://owner-api.teslamotors.com/api/1/vehicles/<YOUR SPECIFIC VEHICLE ID HERE>/data_request/vehicle_state", headers={'Authorization' : 'Bearer %s' % access_token})
    vehicle_req_resp = urlopen(vehicle_req)
    vehicle_data = json.loads(vehicle_req_resp.read())
    the_response = vehicle_data['response']
    # There's all kinds of cool data here but odometer is what I chose
    return the_response['odometer']
	
def lambda_handler(event, context):
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': "This Tesla has %s miles on it - reported on request from AWS IoT Button!" % getTeslaInfo()
    }

    req = Request(HOOK_URL, json.dumps(slack_message))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
